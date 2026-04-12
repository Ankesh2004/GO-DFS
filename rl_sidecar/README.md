# RL Placement Sidecar

A DDPG-based placement optimizer that runs alongside each GO-DFS node.

## Setup

```bash
cd rl_sidecar
pip install -r requirements.txt
```

## Running

```bash
# default port 5100
python server.py

# custom port
RL_PORT=5200 python server.py
```

## How it works

The Go node sends candidate profiles (hardware tier, latency, cost, uptime, RTT) to this sidecar via HTTP. The DDPG agent scores each candidate and returns the optimal `R` nodes for chunk placement.

### Three reward signals

1. **Dense immediate** — profile-estimated latency + cost + reliability penalty on every placement
2. **Trust calibration** — heartbeat RTT vs claimed latency divergence (continuous)
3. **Eviction penalty** — `-100` reward retroactively applied when a node dies

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/optimize_placement` | Pick best R nodes from K candidates |
| POST | `/record_outcome` | Report actual placement latency |
| POST | `/record_eviction` | Node died — apply penalty |
| POST | `/calibrate_trust` | Heartbeat RTT for trust scoring |
| GET | `/health` | Status check |

### Heuristic Bootstrap

For the first 500 placements, the agent uses a weighted heuristic scorer (uptime × 2 - latency × 0.1 - cost × 10) instead of the neural network. This gives decent day-1 performance while the DDPG model collects training data.

## Configuration

Edit `config.py` to tune reward weights, network architecture, and exploration parameters.
