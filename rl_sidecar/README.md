# 🧠 RL Placement Sidecar

> "the brain behind where your data actually goes."

Hey! So this is the Python RL sidecar for GO-DFS. It runs alongside each Go node and uses a **Deep Deterministic Policy Gradient (DDPG)** agent to figure out the absolute best nodes to place our chunks on. 

We had to build this because simple heuristics just don't cut it when you have a bunch of P2P nodes lying about their latency.

## 🏗️ Environment

The agent takes in a bunch of candidate nodes (up to `K` candidates, default 20) and spits out the top `R` nodes. 
Each candidate has a feature vector of 11 dimensions:
- **Performance**: Latency (claimed vs actual RTT), bandwidth, available capacity.
- **Cost**: Cost per GB/hour.
- **Reliability**: Uptime ratio, avg session length, hardware tier (NVMe, SSD, HDD).
- **Trust**: Divergence between claimed latency and actual heartbeat RTT.

<!-- honestly the trust metric is super important here, it basically catches nodes that are spoofing their stats to get more traffic. -->

## 🎯 Reward Function

Getting the reward right was tricky, so it's split into three signals:

1. **Phase A (Immediate Dense Reward)**: We give it instant feedback based on the profile estimates. It's a weighted sum of latency, cost, reliability, capacity, and trust divergence. 
2. **Phase B (Trust Calibration)**: Continuous updates based on heartbeat RTTs. If a node is lagging, the agent learns to avoid it.
3. **Phase C (Retroactive Eviction Penalty)**: This is the cool part. If a node suddenly dies, we go back in time (credit assignment) and slap a massive penalty (`-100`) on past placements that picked this dead node. It literally learns from its past mistakes!

## 🤖 Inference Model

- **Architecture**: DDPG (Actor-Critic). Both networks use 2 hidden layers of 128 units.
- **Actor**: Maps candidate state vectors to action scores (higher is better).
- **Critic**: Estimates the Q-value of the placement decision.
- **Exploration**: Uses Ornstein-Uhlenbeck (OU) noise so the agent tries new nodes sometimes instead of just sticking to the same old ones.

<!-- note: for the first 500 steps, we just use a basic heuristic math formula so the day-1 performance isn't complete garbage while the neural net warms up. -->

## 🔌 Integration with the Go node via ZeroMQ

While the current `server.py` implementation exposes a Flask HTTP API for testing, the production architecture integrates with the Go node via **ZeroMQ** for ultra-low latency IPC. 

The Go node fires over the candidate profiles via a ZMQ socket, and the Python sidecar shoots back the selected targets and a `placement_id` to track it. 

### Current Endpoints (HTTP fallback)
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/optimize_placement` | Get the top R nodes |
| `POST` | `/record_outcome` | Tell the agent how the latency actually was |
| `POST` | `/record_eviction` | Node dropped! Apply the retroactive penalty |
| `POST` | `/calibrate_trust` | Feed in heartbeat RTTs |
| `GET`  | `/health` | Check warmup status and buffer sizes |

## 🚀 Setup & Running

```bash
cd rl_sidecar
pip install -r requirements.txt

# Start the sidecar (default port 5100)
python server.py
```

<!-- Don't forget to tweak config.py if you want to change the reward weights! For example, crank up W_RELIABILITY if nodes keep churning. -->
