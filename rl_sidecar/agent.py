import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import uuid
from collections import defaultdict

import config
from replay_buffer import ReplayBuffer, OUNoise


class Actor(nn.Module):
    """
    maps state (candidate features) to action scores.
    the top-R scoring candidates get selected for placement.
    """

    def __init__(self, state_dim, action_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, config.HIDDEN_DIM),
            nn.ReLU(),
            nn.Linear(config.HIDDEN_DIM, config.HIDDEN_DIM),
            nn.ReLU(),
            nn.Linear(config.HIDDEN_DIM, action_dim),
            nn.Tanh(),  # scores in [-1, 1], higher = more preferred
        )

    def forward(self, state):
        return self.net(state)


class Critic(nn.Module):
    """
    estimates Q(state, action) — how good is this placement decision
    given the current network state.
    """

    def __init__(self, state_dim, action_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim + action_dim, config.HIDDEN_DIM),
            nn.ReLU(),
            nn.Linear(config.HIDDEN_DIM, config.HIDDEN_DIM),
            nn.ReLU(),
            nn.Linear(config.HIDDEN_DIM, 1),
        )

    def forward(self, state, action):
        return self.net(torch.cat([state, action], dim=-1))


class DDPGAgent:
    """
    Deep Deterministic Policy Gradient agent for multi-objective placement.

    three reward signals feed into this agent:
    1) immediate dense reward from profile-estimated latency/cost/reliability
    2) continuous trust calibration from heartbeat RTT divergence
    3) retroactive eviction penalty when a node dies

    the agent maintains placement history so eviction penalties can be applied
    backward in time (credit assignment).
    """

    def __init__(self, max_candidates=config.MAX_CANDIDATES):
        self.max_candidates = max_candidates
        state_dim = max_candidates * config.FEATURES_PER_CANDIDATE
        action_dim = max_candidates

        # main networks
        self.actor = Actor(state_dim, action_dim)
        self.critic = Critic(state_dim, action_dim)

        # target networks (soft-updated for stability)
        self.actor_target = Actor(state_dim, action_dim)
        self.critic_target = Critic(state_dim, action_dim)
        self.actor_target.load_state_dict(self.actor.state_dict())
        self.critic_target.load_state_dict(self.critic.state_dict())

        self.actor_optimizer = optim.Adam(self.actor.parameters(), lr=config.ACTOR_LR)
        self.critic_optimizer = optim.Adam(self.critic.parameters(), lr=config.CRITIC_LR)

        self.replay_buffer = ReplayBuffer(config.REPLAY_BUFFER_SIZE)
        self.noise = OUNoise(action_dim, sigma=config.NOISE_SIGMA, theta=config.NOISE_THETA)

        # placement tracking for retroactive eviction penalties
        # maps placement_id -> {targets: [addrs], state: np.array, action: np.array}
        self.placement_history = {}
        self.placement_order = []  # ordered list of placement IDs for FIFO cleanup

        # trust calibration — maps addr -> trust_divergence score
        self.peer_trust = defaultdict(float)

        self.total_steps = 0
        self.model_version = 0

    def _build_feature_vector(self, candidates):
        """
        converts the raw candidate list into a fixed-size feature tensor.
        pads with zeros if fewer than MAX_CANDIDATES are provided.
        """
        features = np.zeros(self.max_candidates * config.FEATURES_PER_CANDIDATE, dtype=np.float32)

        for i, c in enumerate(candidates[:self.max_candidates]):
            offset = i * config.FEATURES_PER_CANDIDATE

            # one-hot encode the tier (3 values: nvme=0, ssd=1, hdd=2)
            tier = int(c.get("tier", 1))
            tier_onehot = [0.0, 0.0, 0.0]
            if 0 <= tier <= 2:
                tier_onehot[tier] = 1.0

            # compute trust divergence — how much is this node lying about latency?
            claimed = max(c.get("latency_ms", 1.0), 0.01)  # avoid div by zero
            rtt = c.get("heartbeat_rtt_ms", claimed)
            trust_div = abs(rtt - claimed) / claimed

            # also check if we have a cached trust score from /calibrate_trust
            addr = c.get("addr", "")
            if addr in self.peer_trust:
                trust_div = max(trust_div, self.peer_trust[addr])

            features[offset:offset + config.FEATURES_PER_CANDIDATE] = [
                c.get("latency_ms", 5.0) / 100.0,           # normalize to ~[0, 1]
                c.get("cost_per_gb_hour", 0.01) * 100.0,     # scale up small costs
                c.get("available_mb", 10000) / 100000.0,      # normalize to ~[0, 1]
                c.get("bandwidth_mbps", 100.0) / 1000.0,      # normalize
                tier_onehot[0], tier_onehot[1], tier_onehot[2],
                c.get("uptime_ratio", 0.5),                   # already 0-1
                min(c.get("avg_session_sec", 0) / 3600.0, 1.0),  # normalize to hours
                rtt / 100.0,                                   # normalize RTT
                min(trust_div, 5.0) / 5.0,                     # cap at 5x divergence
            ]

        return features

    def _compute_reward(self, candidates, selected_indices):
        """
        immediate dense reward based on profile estimates.
        this is the Phase A reward — fast feedback for the neural net.
        """
        if not selected_indices:
            return 0.0

        total_latency = 0.0
        total_cost = 0.0
        total_pfail = 0.0
        total_capacity = 0.0
        total_trust_div = 0.0

        for idx in selected_indices:
            c = candidates[idx]
            total_latency += c.get("latency_ms", 5.0)
            total_cost += c.get("cost_per_gb_hour", 0.01)
            total_pfail += (1.0 - c.get("uptime_ratio", 0.5))

            available = c.get("available_mb", 0)
            total_capacity += min(available / 10000.0, 1.0)

            # trust divergence penalty
            claimed = max(c.get("latency_ms", 1.0), 0.01)
            rtt = c.get("heartbeat_rtt_ms", claimed)
            total_trust_div += abs(rtt - claimed) / claimed

        n = len(selected_indices)
        reward = (
            -config.W_LATENCY * (total_latency / n)
            - config.W_COST * total_cost
            - config.W_RELIABILITY * (total_pfail / n)
            + config.W_CAPACITY * (total_capacity / n)
            - config.W_TRUST * (total_trust_div / n)
        )
        return reward

    def select_targets(self, candidates, needed):
        """
        given K candidates with full profiles, returns the best R=needed addresses.
        uses the actor network when we have enough training data,
        otherwise falls back to heuristic scoring for bootstrap performance.
        """
        n_candidates = min(len(candidates), self.max_candidates)
        state = self._build_feature_vector(candidates)

        if self.total_steps < config.WARMUP_STEPS:
            # heuristic bootstrap — weighted scoring so day-1 performance isn't garbage.
            # the RL agent will learn to beat this over time.
            scores = []
            for c in candidates[:n_candidates]:
                uptime = c.get("uptime_ratio", 0.5)
                latency = c.get("latency_ms", 5.0)
                cost = c.get("cost_per_gb_hour", 0.01)
                # higher score = better candidate
                score = uptime * 2.0 - latency * 0.1 - cost * 10.0
                scores.append(score)
            sorted_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
            selected = sorted_idx[:needed]
        else:
            # actor network + exploration noise
            state_tensor = torch.FloatTensor(state).unsqueeze(0)
            with torch.no_grad():
                action = self.actor(state_tensor).squeeze(0).numpy()

            # add OU noise for exploration
            noise = self.noise.sample()[:n_candidates]
            action[:n_candidates] += noise

            # pick the top-R scoring candidates
            candidate_scores = action[:n_candidates]
            selected = np.argsort(candidate_scores)[-needed:][::-1].tolist()

        # generate a placement ID for tracking
        placement_id = str(uuid.uuid4())[:8]

        # build action vector for the replay buffer
        action_vec = np.zeros(self.max_candidates, dtype=np.float32)
        for idx in selected:
            action_vec[idx] = 1.0

        # compute immediate reward
        reward = self._compute_reward(candidates[:n_candidates], selected)

        # store in replay buffer for training
        # (next_state is the same as state for now — gets updated on next placement)
        self.replay_buffer.push(state, action_vec, reward, state, False)

        # record placement for retroactive eviction penalties
        target_addrs = [candidates[i].get("addr", "") for i in selected]
        self.placement_history[placement_id] = {
            "targets": target_addrs,
            "state": state.copy(),
            "action": action_vec.copy(),
            "reward": reward,
        }
        self.placement_order.append(placement_id)

        # cleanup old history if it gets too big
        while len(self.placement_order) > config.PLACEMENT_HISTORY_SIZE:
            old_id = self.placement_order.pop(0)
            self.placement_history.pop(old_id, None)

        self.total_steps += 1

        # train if we have enough samples
        if len(self.replay_buffer) >= config.BATCH_SIZE:
            self._train_step()

        return target_addrs, placement_id

    def record_outcome(self, placement_id, actual_latency, success):
        """
        the Go node reports how a placement actually went.
        we use this to adjust the reward retroactively — the empirical
        latency might differ from the profile estimate.
        """
        if placement_id not in self.placement_history:
            return

        entry = self.placement_history[placement_id]
        # retroactive reward adjustment based on actual vs estimated performance
        latency_bonus = -config.W_LATENCY * actual_latency / 100.0
        if not success:
            latency_bonus -= 10.0  # extra penalty for failed placements

        adjusted_reward = entry["reward"] + latency_bonus
        self.replay_buffer.push(
            entry["state"], entry["action"], adjusted_reward, entry["state"], False
        )

    def record_eviction(self, evicted_addr):
        """
        a node just died. apply a massive negative reward to every recent
        placement that targeted this node. this is the credit assignment
        mechanism — the agent learns that past decisions have consequences.
        """
        penalties_applied = 0
        for pid in reversed(self.placement_order[-200:]):
            entry = self.placement_history.get(pid)
            if entry and evicted_addr in entry["targets"]:
                penalty_reward = -config.EVICTION_PENALTY
                self.replay_buffer.push(
                    entry["state"], entry["action"], penalty_reward, entry["state"], True
                )
                penalties_applied += 1

        # extra training to absorb the penalty signal quickly
        if penalties_applied > 0 and len(self.replay_buffer) >= config.BATCH_SIZE:
            for _ in range(min(penalties_applied, 10)):
                self._train_step()

        return penalties_applied

    def calibrate_trust(self, addr, claimed_latency, heartbeat_rtt):
        """
        updates the trust divergence score for a peer.
        called on every heartbeat — if the divergence is consistently high,
        the RL agent will learn to deprioritize this node.
        """
        if claimed_latency <= 0:
            claimed_latency = 1.0
        divergence = abs(heartbeat_rtt - claimed_latency) / claimed_latency

        # exponential moving average so one bad ping doesn't ruin a node's rep
        alpha = 0.3
        old = self.peer_trust.get(addr, 0.0)
        self.peer_trust[addr] = alpha * divergence + (1 - alpha) * old

        return self.peer_trust[addr]

    def _train_step(self):
        """one gradient step on both actor and critic."""
        states, actions, rewards, next_states, dones = self.replay_buffer.sample(config.BATCH_SIZE)

        states_t = torch.FloatTensor(states)
        actions_t = torch.FloatTensor(actions)
        rewards_t = torch.FloatTensor(rewards)
        next_states_t = torch.FloatTensor(next_states)
        dones_t = torch.FloatTensor(dones)

        # critic update: minimize TD error
        with torch.no_grad():
            next_actions = self.actor_target(next_states_t)
            target_q = self.critic_target(next_states_t, next_actions)
            target_value = rewards_t + config.GAMMA * (1 - dones_t) * target_q

        current_q = self.critic(states_t, actions_t)
        critic_loss = nn.MSELoss()(current_q, target_value)

        self.critic_optimizer.zero_grad()
        critic_loss.backward()
        self.critic_optimizer.step()

        # actor update: maximize Q(s, actor(s))
        predicted_actions = self.actor(states_t)
        actor_loss = -self.critic(states_t, predicted_actions).mean()

        self.actor_optimizer.zero_grad()
        actor_loss.backward()
        self.actor_optimizer.step()

        # soft-update target networks
        for target_param, param in zip(self.actor_target.parameters(), self.actor.parameters()):
            target_param.data.copy_(config.TAU * param.data + (1 - config.TAU) * target_param.data)
        for target_param, param in zip(self.critic_target.parameters(), self.critic.parameters()):
            target_param.data.copy_(config.TAU * param.data + (1 - config.TAU) * target_param.data)

        self.model_version += 1

    def get_stats(self):
        """quick snapshot for the /health endpoint."""
        return {
            "model_version": self.model_version,
            "total_steps": self.total_steps,
            "replay_buffer_size": len(self.replay_buffer),
            "tracked_placements": len(self.placement_history),
            "tracked_peers_trust": len(self.peer_trust),
            "warmup_remaining": max(0, config.WARMUP_STEPS - self.total_steps),
        }
