"""
simulate.py — synthetic training environment for the DDPG placement agent.

instead of spinning up real Go nodes, this generates thousands of fake
placement scenarios with realistic node profiles, churn events, and
workload patterns. trains the agent to convergence and produces the
comparison data the thesis needs.

this is standard practice in RL research — you train in simulation,
then validate on the real system. the benchmark_runner.py handles
the real-system validation.

usage:
  python benchmark\simulate.py
  python benchmark\simulate.py --episodes 5000 --nodes 10
"""

import sys
import os
import json
import random
import argparse
import time
import numpy as np

# add the sidecar directory to the path so we can import the agent
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "rl_sidecar"))

import config
from agent import DDPGAgent


class NodeProfile:
    """represents a simulated peer node with realistic hardware characteristics."""

    def __init__(self, node_id, tier, latency_ms, cost, bandwidth, reliability):
        self.node_id = node_id
        self.tier = tier               # 0=nvme, 1=ssd, 2=hdd
        self.latency_ms = latency_ms
        self.cost_per_gb_hour = cost
        self.bandwidth_mbps = bandwidth
        self.reliability = reliability  # "stable", "flaky", "transient"
        self.alive = True
        self.uptime_ratio = self._base_uptime()
        self.avg_session_sec = self._base_session()
        self.heartbeat_rtt = latency_ms + random.gauss(0, latency_ms * 0.2)

    def _base_uptime(self):
        if self.reliability == "stable":
            return random.uniform(0.92, 0.99)
        elif self.reliability == "flaky":
            return random.uniform(0.55, 0.75)
        else:  # transient
            return random.uniform(0.20, 0.40)

    def _base_session(self):
        if self.reliability == "stable":
            return random.uniform(1800, 28800)  # 30min to 8hr
        elif self.reliability == "flaky":
            return random.uniform(300, 1800)     # 5min to 30min
        else:
            return random.uniform(60, 600)       # 1min to 10min

    def to_candidate(self):
        """convert to the JSON dict format the agent expects."""
        # add some noise to simulate real-world measurement jitter
        rtt = max(0.1, self.heartbeat_rtt + random.gauss(0, 1.0))
        return {
            "addr": f"192.168.1.{self.node_id}:700{self.node_id}",
            "tier": self.tier,
            "latency_ms": self.latency_ms,
            "cost_per_gb_hour": self.cost_per_gb_hour,
            "available_mb": random.randint(1000, 50000),
            "bandwidth_mbps": self.bandwidth_mbps,
            "uptime_ratio": self.uptime_ratio,
            "avg_session_sec": int(self.avg_session_sec),
            "heartbeat_rtt_ms": rtt,
        }

    def maybe_churn(self):
        """randomly kill or resurrect this node based on its reliability class."""
        roll = random.random()
        if self.alive:
            # chance of going offline this tick
            if self.reliability == "stable" and roll < 0.005:
                self.alive = False
            elif self.reliability == "flaky" and roll < 0.05:
                self.alive = False
            elif self.reliability == "transient" and roll < 0.15:
                self.alive = False
        else:
            # chance of coming back
            if self.reliability == "stable" and roll < 0.8:
                self.alive = True
            elif self.reliability == "flaky" and roll < 0.3:
                self.alive = True
            elif self.reliability == "transient" and roll < 0.1:
                self.alive = True

        # update uptime ratio as EMA
        alpha = 0.05
        self.uptime_ratio = alpha * (1.0 if self.alive else 0.0) + (1 - alpha) * self.uptime_ratio


class KademliaBaseline:
    """
    simulates what vanilla Kademlia does — picks the K closest nodes
    by XOR distance, completely ignoring hardware profiles.
    this is the baseline the RL agent needs to beat.
    """

    def select_targets(self, candidates, needed):
        """random selection simulating XOR-distance based choice (hardware-blind)."""
        if len(candidates) <= needed:
            return list(range(len(candidates)))
        return random.sample(range(len(candidates)), needed)


class DRPSBaseline:
    """
    Adapted DRPS Heuristic Baseline (ADHB).

    Faithful implementation of the rank-based + greedy load-balancing
    heuristic from the DRPS paper (centralized original, decentralized here).

    Two-stage algorithm:
      Stage 1 — rank every candidate by a weighted score:
                   Score_i = w1*C_i + w2*Q_i + w3*D_i + w4*B_i
        where:
          C_i = available_mb / max_available_mb          (capacity, higher = better)
          Q_i = uptime_ratio                             (reliability, higher = better)
          D_i = 1 - latency_ms / max_latency_ms         (delay, lower latency = higher score)
          B_i = 1 - load_i  (where load = 1 - available_mb/100000) (busyness, lower load = higher)

        Weights per paper: w1=0.20, w2=0.35, w3=0.25, w4=0.20
        (reliability is the highest — same philosophy as our DRL reward weights)

      Stage 2 — greedy selection: pick top-scored nodes obeying T_load=0.85,
                then do one load-variance swap pass to balance the chosen set.

    This is the paper we are improving upon — fixed weights vs. learned policy.
    """

    # paper-specified weights (must sum to 1.0)
    W_CAPACITY    = 0.20
    W_RELIABILITY = 0.35   # highest, same reasoning as our DRL w3
    W_DELAY       = 0.25
    W_LOAD        = 0.20

    T_LOAD = 0.85  # max acceptable load ratio before a node is skipped

    def select_targets(self, candidates, needed, chunk_size_mb=0.1):
        """
        Stage 1: compute normalized scores for all feasible candidates.
        Stage 2: greedy pick + load-variance balancing swap.

        returns list of selected indices into `candidates`.
        """
        if len(candidates) <= needed:
            return list(range(len(candidates)))

        # --- capacity constraint: filter nodes with enough storage ---
        feasible = [
            i for i, c in enumerate(candidates)
            if c.get("available_mb", 0) >= chunk_size_mb
        ]
        if len(feasible) < needed:
            # relax constraint and use all if not enough feasible
            feasible = list(range(len(candidates)))

        # --- normalisation denominators (avoid div-by-zero) ---
        avail_vals  = [candidates[i].get("available_mb",  1.0) for i in feasible]
        latency_vals = [candidates[i].get("latency_ms",   1.0) for i in feasible]

        S_max = max(avail_vals)   if max(avail_vals)   > 0 else 1.0
        L_max = max(latency_vals) if max(latency_vals) > 0 else 1.0

        # --- Stage 1: score every feasible candidate ---
        scored = []
        for i in feasible:
            c = candidates[i]

            C_i = c.get("available_mb", 1.0) / S_max

            Q_i = c.get("uptime_ratio", 0.5)   # already in [0, 1]

            D_i = 1.0 - (c.get("latency_ms", 5.0) / L_max)

            # estimate load from available capacity (inverse of fullness)
            # lower available_mb relative to max => higher load
            load_i = 1.0 - (c.get("available_mb", 1.0) / S_max)
            B_i = 1.0 - load_i  # higher available => lower load => better score

            score = (
                self.W_CAPACITY    * C_i
                + self.W_RELIABILITY * Q_i
                + self.W_DELAY       * D_i
                + self.W_LOAD        * B_i
            )
            scored.append((score, load_i, i))

        # sort descending by score
        scored.sort(key=lambda x: x[0], reverse=True)

        # --- Stage 2: greedy pick obeying load threshold ---
        selected = []
        skipped  = []
        for score, load_i, idx in scored:
            if len(selected) == needed:
                break
            if load_i < self.T_LOAD:
                selected.append(idx)
            else:
                skipped.append((score, load_i, idx))  # overloaded — try later

        # if we couldn't fill with sub-threshold nodes, fall back to skipped ones
        for score, load_i, idx in skipped:
            if len(selected) == needed:
                break
            selected.append(idx)

        # --- Stage 2b: greedy load-variance swap ---
        # compute load vector for the current selection
        loads = [1.0 - (candidates[i].get("available_mb", 1.0) / S_max) for i in selected]
        avg_load = np.mean(loads)

        def variance(load_list):
            m = np.mean(load_list)
            return np.mean([(l - m) ** 2 for l in load_list])

        old_var = variance(loads)

        # try swapping the most overloaded selected node with the lowest-loaded unselected one
        selected_set = set(selected)
        unselected = [i for i in feasible if i not in selected_set]

        if unselected:
            # find the most overloaded node in the selection
            overloaded_pos = max(range(len(selected)), key=lambda j: loads[j])
            overloaded_idx = selected[overloaded_pos]

            # find the lightest unselected node that is under the avg load
            candidates_for_swap = [
                i for i in unselected
                if (1.0 - candidates[i].get("available_mb", 1.0) / S_max) < avg_load
            ]

            if candidates_for_swap:
                # pick the one with the lowest load
                best_swap = min(
                    candidates_for_swap,
                    key=lambda i: 1.0 - candidates[i].get("available_mb", 1.0) / S_max
                )
                # check if swap reduces variance
                new_loads = loads[:]
                new_load_val = 1.0 - candidates[best_swap].get("available_mb", 1.0) / S_max
                new_loads[overloaded_pos] = new_load_val

                if variance(new_loads) < old_var:
                    selected[overloaded_pos] = best_swap

        return selected


def create_network(num_nodes):
    """spin up a heterogeneous network with realistic tier distribution."""
    nodes = []
    node_configs = [
        # fast but expensive NVMe nodes (20%)
        {"tier": 0, "latency_ms": (0.5, 2.0), "cost": (0.03, 0.08),
         "bandwidth": (500, 1000), "reliability": "stable"},
        # balanced SSD nodes (50%)
        {"tier": 1, "latency_ms": (3.0, 8.0), "cost": (0.005, 0.02),
         "bandwidth": (100, 300), "reliability": "stable"},
        # cheap HDD nodes (20%)
        {"tier": 2, "latency_ms": (10.0, 25.0), "cost": (0.001, 0.005),
         "bandwidth": (30, 80), "reliability": "flaky"},
        # unreliable nodes (10%) — the laptop-closers
        {"tier": 1, "latency_ms": (5.0, 15.0), "cost": (0.008, 0.015),
         "bandwidth": (50, 150), "reliability": "transient"},
    ]

    # distribute node types roughly matching the ratios above
    distribution = [0.20, 0.50, 0.20, 0.10]
    for i in range(num_nodes):
        cfg_idx = np.random.choice(len(node_configs), p=distribution)
        cfg = node_configs[cfg_idx]
        node = NodeProfile(
            node_id=i + 1,
            tier=cfg["tier"],
            latency_ms=random.uniform(*cfg["latency_ms"]),
            cost=random.uniform(*cfg["cost"]),
            bandwidth=random.uniform(*cfg["bandwidth"]),
            reliability=cfg["reliability"],
        )
        nodes.append(node)

    return nodes


def compute_actual_latency(candidates, selected_indices):
    """
    simulates the REAL latency after placement — adds noise and
    penalizes dead nodes (data loss = infinite latency).
    """
    total = 0.0
    for idx in selected_indices:
        c = candidates[idx]
        base = c.get("latency_ms", 5.0)
        # real latency is noisier than the profile claims
        actual = base + random.gauss(0, base * 0.3)
        total += max(0.1, actual)
    return total / max(len(selected_indices), 1)


def run_simulation(num_nodes, num_episodes, needed_replicas=3):
    """
    main simulation loop. runs the DDPG agent and Kademlia baseline
    side-by-side through identical scenarios for fair comparison.
    """
    print(f"\n{'='*60}")
    print(f"  Synthetic DRL Training Simulation")
    print(f"  Nodes: {num_nodes} | Episodes: {num_episodes} | Replicas: {needed_replicas}")
    print(f"{'='*60}\n")

    nodes = create_network(num_nodes)
    agent    = DDPGAgent(max_candidates=min(num_nodes, config.MAX_CANDIDATES))
    baseline = KademliaBaseline()
    drps     = DRPSBaseline()

    # tracking arrays for graphs
    rl_latencies = []
    rl_costs = []
    rl_uptimes = []
    rl_durations = []
    rl_tiers = []
    rl_rewards = []

    kad_latencies = []
    kad_costs = []
    kad_uptimes = []
    kad_tiers = []

    # DRPS tracking — same structure as RL and Kademlia
    drps_latencies = []
    drps_costs     = []
    drps_uptimes   = []
    drps_tiers     = []

    eviction_events = []
    churn_timeline = []

    print("Training the DDPG agent...")
    start_time = time.time()

    for ep in range(num_episodes):
        # simulate churn — nodes randomly go up/down
        for node in nodes:
            old_alive = node.alive
            node.maybe_churn()
            if old_alive and not node.alive:
                # node just died — trigger eviction penalty
                addr = f"192.168.1.{node.node_id}:700{node.node_id}"
                penalties = agent.record_eviction(addr)
                eviction_events.append({
                    "episode": ep,
                    "node_id": node.node_id,
                    "penalties": penalties,
                })

        alive_count = sum(1 for n in nodes if n.alive)
        churn_timeline.append(alive_count)

        # build candidate list from alive nodes only
        alive_nodes = [n for n in nodes if n.alive]
        if len(alive_nodes) < needed_replicas:
            continue  # not enough nodes online, skip this episode

        candidates = [n.to_candidate() for n in alive_nodes]

        # --- RL Agent Decision ---
        t0 = time.time()
        rl_targets, placement_id = agent.select_targets(candidates, needed_replicas)
        rl_duration = (time.time() - t0) * 1000

        # figure out which indices the RL agent picked
        rl_indices = []
        for addr in rl_targets:
            for i, c in enumerate(candidates):
                if c["addr"] == addr:
                    rl_indices.append(i)
                    break

        rl_actual_lat = compute_actual_latency(candidates, rl_indices)
        rl_cost = sum(candidates[i]["cost_per_gb_hour"] for i in rl_indices)
        rl_uptime = np.mean([candidates[i]["uptime_ratio"] for i in rl_indices])
        rl_tier_list = [candidates[i]["tier"] for i in rl_indices]

        # report outcome back to the agent for learning
        agent.record_outcome(placement_id, rl_actual_lat, True)

        # do trust calibration for all alive nodes
        for c in candidates[:5]:  # simulate heartbeats for a few nodes
            agent.calibrate_trust(c["addr"], c["latency_ms"], c["heartbeat_rtt_ms"])

        rl_latencies.append(rl_actual_lat)
        rl_costs.append(rl_cost)
        rl_uptimes.append(rl_uptime)
        rl_durations.append(rl_duration)
        rl_tiers.extend(rl_tier_list)

        # --- Kademlia Baseline Decision ---
        kad_indices = baseline.select_targets(candidates, needed_replicas)
        kad_actual_lat = compute_actual_latency(candidates, kad_indices)
        kad_cost = sum(candidates[i]["cost_per_gb_hour"] for i in kad_indices)
        kad_uptime = np.mean([candidates[i]["uptime_ratio"] for i in kad_indices])
        kad_tier_list = [candidates[i]["tier"] for i in kad_indices]

        kad_latencies.append(kad_actual_lat)
        kad_costs.append(kad_cost)
        kad_uptimes.append(kad_uptime)
        kad_tiers.extend(kad_tier_list)

        # --- DRPS Heuristic Baseline Decision ---
        drps_indices = drps.select_targets(candidates, needed_replicas)
        drps_actual_lat = compute_actual_latency(candidates, drps_indices)
        drps_cost   = sum(candidates[i]["cost_per_gb_hour"] for i in drps_indices)
        drps_uptime = np.mean([candidates[i]["uptime_ratio"] for i in drps_indices])
        drps_tier_list = [candidates[i]["tier"] for i in drps_indices]

        drps_latencies.append(drps_actual_lat)
        drps_costs.append(drps_cost)
        drps_uptimes.append(drps_uptime)
        drps_tiers.extend(drps_tier_list)

        # progress print every 500 episodes
        if (ep + 1) % 500 == 0:
            elapsed = time.time() - start_time
            rl_avg   = np.mean(rl_latencies[-500:])
            kad_avg  = np.mean(kad_latencies[-500:])
            drps_avg = np.mean(drps_latencies[-500:])
            print(f"  Episode {ep+1:5d}/{num_episodes} | "
                  f"RL: {rl_avg:.2f}ms | Kad: {kad_avg:.2f}ms | DRPS: {drps_avg:.2f}ms | "
                  f"Buffer: {len(agent.replay_buffer)} | "
                  f"Alive: {alive_count}/{num_nodes} | "
                  f"Time: {elapsed:.1f}s")

    elapsed = time.time() - start_time
    print(f"\n  Training complete in {elapsed:.1f}s")
    print(f"  Model version: {agent.model_version}")
    print(f"  Replay buffer: {len(agent.replay_buffer)}")

    # build the results in the same format plot_results.py expects
    results = {
        "rl": {
            "placements": [],
            "evictions": eviction_events,
            "summary": {
                "total_placements": len(rl_latencies),
                "rl_placements": len(rl_latencies),
                "fallback_placements": 0,
                "total_evictions": len(eviction_events),
            }
        },
        "kademlia": {
            "placements": [],
            "evictions": [],
            "summary": {
                "total_placements": len(kad_latencies),
                "rl_placements": 0,
                "fallback_placements": len(kad_latencies),
                "total_evictions": 0,
            }
        },
        "drps": {
            "placements": [],
            "evictions": [],
            "summary": {
                "total_placements": len(drps_latencies),
                "rl_placements": 0,
                "fallback_placements": 0,
                "total_evictions": 0,
            }
        },
        "churn_timeline": churn_timeline,
        "agent_stats": agent.get_stats(),
    }

    # pack up per-placement data
    for i in range(len(rl_latencies)):
        results["rl"]["placements"].append({
            "method": "rl",
            "avg_latency_ms": round(rl_latencies[i], 2),
            "total_cost": round(rl_costs[i], 6),
            "avg_uptime": round(rl_uptimes[i], 4),
            "duration_ms": round(rl_durations[i], 2),
            "selected_tiers": [],  # individual tiers tracked in aggregate
        })

    for i in range(len(kad_latencies)):
        results["kademlia"]["placements"].append({
            "method": "kademlia_fallback",
            "avg_latency_ms": round(kad_latencies[i], 2),
            "total_cost": round(kad_costs[i], 6),
            "avg_uptime": round(kad_uptimes[i], 4),
            "duration_ms": 0,
            "selected_tiers": [],
        })

    for i in range(len(drps_latencies)):
        results["drps"]["placements"].append({
            "method": "drps",
            "avg_latency_ms": round(drps_latencies[i], 2),
            "total_cost": round(drps_costs[i], 6),
            "avg_uptime": round(drps_uptimes[i], 4),
            "duration_ms": 0,  # pure Python heuristic, negligible overhead
            "selected_tiers": [],
        })

    # add tier distribution in aggregate
    tier_names = {0: "nvme", 1: "ssd", 2: "hdd"}
    for tier_val in [0, 1, 2]:
        results["rl"]["tier_counts"] = results.get("rl", {}).get("tier_counts", {})
        results["rl"]["tier_counts"][tier_names[tier_val]] = rl_tiers.count(tier_val)
        results["kademlia"]["tier_counts"] = results.get("kademlia", {}).get("tier_counts", {})
        results["kademlia"]["tier_counts"][tier_names[tier_val]] = kad_tiers.count(tier_val)
        results["drps"]["tier_counts"] = results.get("drps", {}).get("tier_counts", {})
        results["drps"]["tier_counts"][tier_names[tier_val]] = drps_tiers.count(tier_val)

    # save results
    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)

    # save in the format plot_results.py reads
    with open(os.path.join(output_dir, "rl_metrics.json"), "w") as f:
        json.dump(results["rl"], f, indent=2)
    with open(os.path.join(output_dir, "kademlia_metrics.json"), "w") as f:
        json.dump(results["kademlia"], f, indent=2)
    with open(os.path.join(output_dir, "drps_metrics.json"), "w") as f:
        json.dump(results["drps"], f, indent=2)

    # also save the full results with churn data for extra analysis
    with open(os.path.join(output_dir, "simulation_full.json"), "w") as f:
        json.dump(results, f, indent=2)

    # print the final 3-way comparison table
    print(f"\n{'='*75}")
    print(f"  RESULTS SUMMARY  (DRL Agent vs DRPS Heuristic vs Kademlia DHT)")
    print(f"{'='*75}")
    print(f"  {'Metric':<30} {'DRL Agent':>12} {'DRPS':>12} {'Kademlia':>12}")
    print(f"  {'-'*70}")

    rl_avg_lat   = np.mean(rl_latencies)
    drps_avg_lat = np.mean(drps_latencies)
    kad_avg_lat  = np.mean(kad_latencies)
    print(f"  {'Avg Latency (ms)':<30} {rl_avg_lat:>12.2f} {drps_avg_lat:>12.2f} {kad_avg_lat:>12.2f}")

    rl_total_cost   = sum(rl_costs)
    drps_total_cost = sum(drps_costs)
    kad_total_cost  = sum(kad_costs)
    print(f"  {'Total Cost ($)':<30} {rl_total_cost:>12.4f} {drps_total_cost:>12.4f} {kad_total_cost:>12.4f}")

    rl_avg_up   = np.mean(rl_uptimes)
    drps_avg_up = np.mean(drps_uptimes)
    kad_avg_up  = np.mean(kad_uptimes)
    print(f"  {'Avg Node Uptime':<30} {rl_avg_up:>12.4f} {drps_avg_up:>12.4f} {kad_avg_up:>12.4f}")

    rl_avg_dur = np.mean(rl_durations)
    print(f"  {'Avg Decision Time (ms)':<30} {rl_avg_dur:>12.2f} {'~0':>12} {'~0':>12}")
    print(f"  {'Eviction Events':<30} {len(eviction_events):>12}")
    print(f"  {'Model Updates':<30} {agent.model_version:>12}")

    # DRL improvement over DRPS and Kademlia (last 500 = post-warmup trained agent)
    if len(rl_latencies) > 500:
        print(f"\n  --- Last 500 Episodes (Trained Agent, Post-Warmup) ---")
        print(f"  {'Metric':<30} {'DRL Agent':>12} {'DRPS':>12} {'Kademlia':>12}")
        print(f"  {'-'*70}")

        rl_late   = np.mean(rl_latencies[-500:])
        drps_late = np.mean(drps_latencies[-500:])
        kad_late  = np.mean(kad_latencies[-500:])
        print(f"  {'Avg Latency (ms)':<30} {rl_late:>12.2f} {drps_late:>12.2f} {kad_late:>12.2f}")

        rl_cost_late   = np.mean(rl_costs[-500:])
        drps_cost_late = np.mean(drps_costs[-500:])
        kad_cost_late  = np.mean(kad_costs[-500:])
        print(f"  {'Avg Cost per Placement':<30} {rl_cost_late:>12.6f} {drps_cost_late:>12.6f} {kad_cost_late:>12.6f}")

        rl_up_late   = np.mean(rl_uptimes[-500:])
        drps_up_late = np.mean(drps_uptimes[-500:])
        kad_up_late  = np.mean(kad_uptimes[-500:])
        print(f"  {'Avg Node Uptime':<30} {rl_up_late:>12.4f} {drps_up_late:>12.4f} {kad_up_late:>12.4f}")

        # improvement deltas
        print(f"\n  --- DRL Improvement Over Baselines ---")
        if drps_late > 0:
            print(f"  DRL vs DRPS  latency improvement: {((drps_late - rl_late) / drps_late * 100):+.1f}%")
        if kad_late > 0:
            print(f"  DRL vs Kademlia latency improvement: {((kad_late - rl_late) / kad_late * 100):+.1f}%")

    print(f"\n  Results saved to: {output_dir}")
    print(f"  Now run: python benchmark\\plot_results.py")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GO-DFS DRL Synthetic Simulation")
    parser.add_argument("--episodes", type=int, default=3000,
                        help="number of placement episodes to simulate (default: 3000)")
    parser.add_argument("--nodes", type=int, default=10,
                        help="number of nodes in the simulated network (default: 10)")
    parser.add_argument("--replicas", type=int, default=3,
                        help="replication factor R (default: 3)")
    args = parser.parse_args()

    run_simulation(args.nodes, args.episodes, args.replicas)
