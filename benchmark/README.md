# GO-DFS Benchmark Suite 🚀

<!-- hey, Ankesh here! this readme covers the benchmark suite we use for testing the DRL placement agent against standard Kademlia and DRPS heuristics. make sure your python env is set up before running these scripts! -->

Welcome to the **GO-DFS Benchmark Suite**! This directory contains the tools necessary to evaluate, train, and visualize the performance of our Deep Reinforcement Learning (DDPG) placement agent compared to baseline Kademlia DHT and DRPS heuristic approaches. 

The suite is broken down into simulation environments for fast training, live network runners for real-world testing, and plotting tools for generating thesis-ready graphs. 📊

---

## 📂 Suite Components

### 1. `simulate.py` (Synthetic Training Environment)
Instead of spinning up real Go nodes, this script generates thousands of fake placement scenarios with realistic node profiles, churn events, and workload patterns. It trains the DDPG agent to convergence and produces comparison data.
- **Why?** It's standard practice in RL research to train in simulation before validating on the real system!
- **Usage:**
  ```bash
  # run standard simulation
  python benchmark\simulate.py
  
  # run with custom parameters
  python benchmark\simulate.py --episodes 5000 --nodes 10
  ```

### 2. `benchmark_runner.py` (Live Network Validator)
Runs the full RL vs Kademlia comparison on a live, running GO-DFS swarm. It pushes real files into the mesh, fetches placement metrics directly from the nodes' APIs, and saves the results.
- **Prerequisites:** Nodes and the RL sidecar must already be running.
- **Usage:**
  ```bash
  python benchmark\benchmark_runner.py --mode rl --count 30
  python benchmark\benchmark_runner.py --mode kademlia --count 30
  
  # or run both phases automatically
  python benchmark\benchmark_runner.py --mode both --count 30
  ```

### 3. `test_minimal.ps1` (Minimal Test Harness)
A self-contained PowerShell script that builds the GO-DFS nodes, spins up a local 3-node swarm (NVMe, SSD, HDD), starts the Python RL sidecar in an isolated virtual environment, injects a test file, and prints the metrics.
- **Usage:** Just run it from your PowerShell terminal:
  ```powershell
  .\benchmark\test_minimal.ps1
  ```
<!-- honestly this ps1 script is a lifesaver for quick local testing without messing up the main env. - Ankesh -->

### 4. `plot_results.py` (Visualization)
Reads the generated JSON files from the `results/` folder (produced by either `simulate.py` or `benchmark_runner.py`) and generates beautiful graphs comparing the different placement strategies.
- **Usage:**
  ```bash
  python benchmark\plot_results.py
  ```

### 5. `testbed.yaml` (Central Configuration)
The heart of the benchmark scenarios. Edit this file to tweak node profiles, hardware capabilities (tier, latency, cost, bandwidth, reliability), churn rates, and workloads. No magic numbers scattered across the code!

---

## 📈 Metrics Collected

The benchmark suite tracks a comprehensive set of metrics to evaluate the performance of the placement agents:

| Metric | Description | Goal |
|--------|-------------|------|
| **Avg Latency (ms)** | The actual read latency expected when fetching chunks, including network noise. | Minimize 📉 |
| **Total Cost ($)** | Simulated cost based on the storage tiers used (e.g., NVMe is more expensive than HDD). | Minimize 📉 |
| **Avg Node Uptime** | The reliability score of the selected nodes. Measures how well the agent avoids flaky nodes. | Maximize 📈 |
| **Avg Decision Time (ms)** | The time it takes for the agent/heuristic to compute the placement targets. | Minimize 📉 |
| **Eviction Events** | The number of times data had to be re-replicated due to node death. | Minimize 📉 |
| **Tier Distribution** | Counts of how many chunks were placed on NVMe, SSD, or HDD tiers. | Balance ⚖️ |

---

## 🏃‍♂️ How to Run the Full Thesis Pipeline

1. **Train the Agent:** Run `simulate.py` to let the DDPG agent learn the optimal placement policy over thousands of episodes.
2. **Review Simulated Results:** Run `plot_results.py` to ensure the agent converged and outperformed the DRPS/Kademlia baselines.
3. **Spin up the Real Swarm:** Use `test_minimal.ps1` (or your own deployment script) to start the Go nodes and the RL sidecar.
4. **Run Live Benchmark:** Execute `benchmark_runner.py --mode both` to pump files into the real network and gather live metrics.
5. **Plot Final Results:** Run `plot_results.py` again to generate the final, thesis-ready graphs from the live validation data.

<!-- hit me up if anything breaks, but it should be solid! happy benchmarking! - Ankesh -->
