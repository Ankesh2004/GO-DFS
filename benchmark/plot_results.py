"""
plot_results.py — generates thesis-quality comparison graphs.

reads the JSON metrics dumped by benchmark_runner.py and produces:
  1. Average Placement Latency (RL vs Kademlia)
  2. Cumulative Storage Cost
  3. Storage Tier Distribution
  4. Placement Decision Overhead
  5. Pareto Frontier (Latency vs Cost)
  6. Per-Placement Latency Timeline
  7. Average Uptime of Selected Nodes
  8. Combined Summary Dashboard

usage:
  python benchmark\plot_results.py
  python benchmark\plot_results.py --results-dir benchmark\results
"""

import argparse
import json
import os
import sys
import numpy as np

try:
    import matplotlib
    matplotlib.use("Agg")  # headless backend so it doesn't pop up windows
    import matplotlib.pyplot as plt
    from matplotlib.gridspec import GridSpec
except ImportError:
    print("matplotlib not installed. Run: pip install matplotlib")
    sys.exit(1)

# thesis-quality plot styling
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 12,
    "legend.fontsize": 10,
    "figure.dpi": 150,
    "savefig.dpi": 300,
})

# color palette — accessible and print-friendly
RL_COLOR = "#2563EB"       # blue
KAD_COLOR = "#DC2626"      # red
ACCENT = "#10B981"         # green
NVME_COLOR = "#8B5CF6"     # purple
SSD_COLOR = "#F59E0B"      # amber
HDD_COLOR = "#6B7280"      # gray


def load_metrics(results_dir, label):
    """load the JSON metrics file for a given experiment label."""
    path = os.path.join(results_dir, f"{label}_metrics.json")
    if not os.path.exists(path):
        print(f"[!] Missing: {path}")
        return None
    with open(path, "r") as f:
        return json.load(f)


def extract_placements(metrics, method_filter=None):
    """pull placement records, optionally filtering by method."""
    placements = metrics.get("placements", [])
    if method_filter:
        placements = [p for p in placements if p.get("method") == method_filter]
    return placements


def plot_avg_latency_comparison(rl_placements, kad_placements, output_dir):
    """
    Graph 1: Bar chart comparing average placement latency.
    the most important single number for your thesis abstract.
    """
    rl_lats = [p.get("avg_latency_ms", 0) for p in rl_placements]
    kad_lats = [p.get("avg_latency_ms", 0) for p in kad_placements]

    fig, ax = plt.subplots(figsize=(6, 4))

    means = [np.mean(rl_lats) if rl_lats else 0, np.mean(kad_lats) if kad_lats else 0]
    stds = [np.std(rl_lats) if rl_lats else 0, np.std(kad_lats) if kad_lats else 0]

    bars = ax.bar(["DRL Agent", "Kademlia DHT"], means, yerr=stds,
                  color=[RL_COLOR, KAD_COLOR], capsize=5, width=0.5, edgecolor="white")

    # annotate the bars with actual values
    for bar, mean in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f"{mean:.1f} ms", ha="center", va="bottom", fontweight="bold")

    ax.set_ylabel("Average Placement Latency (ms)")
    ax.set_title("Placement Latency: DRL vs Kademlia DHT")
    ax.set_ylim(0, max(means) * 1.4 if max(means) > 0 else 10)
    ax.grid(axis="y", alpha=0.3)

    plt.savefig(os.path.join(output_dir, "01_avg_latency.png"))
    plt.close()
    print("  [OK] 01_avg_latency.png")


def plot_cumulative_cost(rl_placements, kad_placements, output_dir):
    """
    Graph 2: Cumulative storage cost over time.
    shows the RL agent learns to minimize cost as it trains.
    """
    rl_costs = np.cumsum([p.get("total_cost", 0) for p in rl_placements])
    kad_costs = np.cumsum([p.get("total_cost", 0) for p in kad_placements])

    fig, ax = plt.subplots(figsize=(8, 4))

    ax.plot(range(1, len(rl_costs)+1), rl_costs, color=RL_COLOR, linewidth=2, label="DRL Agent")
    ax.plot(range(1, len(kad_costs)+1), kad_costs, color=KAD_COLOR, linewidth=2,
            label="Kademlia DHT", linestyle="--")

    ax.set_xlabel("Number of Placements")
    ax.set_ylabel("Cumulative Cost ($)")
    ax.set_title("Cumulative Storage Cost Over Time")
    ax.legend()
    ax.grid(alpha=0.3)

    plt.savefig(os.path.join(output_dir, "02_cumulative_cost.png"))
    plt.close()
    print("  [OK] 02_cumulative_cost.png")


def plot_tier_distribution(rl_placements, kad_placements, output_dir, rl_data=None, kad_data=None):
    """
    Graph 3: Which storage tiers did each algorithm prefer?
    shows the RL agent learns to avoid expensive NVMe for bulk storage
    while Kademlia picks blindly based on DHT distance.
    """
    tier_names = {0: "NVMe", 1: "SSD", 2: "HDD"}

    def count_tiers(placements, metrics_data=None):
        counts = {"NVMe": 0, "SSD": 0, "HDD": 0}
        # first try per-placement tiers (from real system)
        for p in placements:
            for t in p.get("selected_tiers", []):
                name = tier_names.get(t, "SSD")
                counts[name] += 1
        # if all zeros, check for aggregate tier_counts (from simulation)
        if sum(counts.values()) == 0 and metrics_data:
            tc = metrics_data.get("tier_counts", {})
            counts["NVMe"] = tc.get("nvme", 0)
            counts["SSD"] = tc.get("ssd", 0)
            counts["HDD"] = tc.get("hdd", 0)
        return counts

    rl_tiers = count_tiers(rl_placements, rl_data)
    kad_tiers = count_tiers(kad_placements, kad_data)

    fig, ax = plt.subplots(figsize=(7, 4))

    x = np.arange(3)
    width = 0.35
    labels = ["NVMe", "SSD", "HDD"]
    colors_tier = [NVME_COLOR, SSD_COLOR, HDD_COLOR]

    rl_vals = [rl_tiers[l] for l in labels]
    kad_vals = [kad_tiers[l] for l in labels]

    bars1 = ax.bar(x - width/2, rl_vals, width, label="DRL Agent", color=RL_COLOR, alpha=0.85)
    bars2 = ax.bar(x + width/2, kad_vals, width, label="Kademlia DHT", color=KAD_COLOR, alpha=0.85)

    ax.set_xlabel("Storage Tier")
    ax.set_ylabel("Number of Chunk Placements")
    ax.set_title("Storage Tier Selection Distribution")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    plt.savefig(os.path.join(output_dir, "03_tier_distribution.png"))
    plt.close()
    print("  [OK] 03_tier_distribution.png")


def plot_decision_overhead(rl_placements, kad_placements, output_dir):
    """
    Graph 4: How long does the RL decision take vs Kademlia?
    important to show the neural network inference doesn't add
    unacceptable overhead to the placement pipeline.
    """
    rl_durations = [p.get("duration_ms", 0) for p in rl_placements]
    kad_durations = [p.get("duration_ms", 0) for p in kad_placements]

    fig, ax = plt.subplots(figsize=(6, 4))

    data = [rl_durations, kad_durations]
    bp = ax.boxplot(data, labels=["DRL Agent", "Kademlia DHT"], patch_artist=True,
                    widths=0.4, showmeans=True,
                    meanprops=dict(marker="D", markerfacecolor="white", markersize=6))

    bp["boxes"][0].set_facecolor(RL_COLOR)
    bp["boxes"][0].set_alpha(0.7)
    bp["boxes"][1].set_facecolor(KAD_COLOR)
    bp["boxes"][1].set_alpha(0.7)

    ax.set_ylabel("Decision Time (ms)")
    ax.set_title("Placement Decision Overhead")
    ax.grid(axis="y", alpha=0.3)

    plt.savefig(os.path.join(output_dir, "04_decision_overhead.png"))
    plt.close()
    print("  [OK] 04_decision_overhead.png")


def plot_pareto_frontier(rl_placements, kad_placements, output_dir):
    """
    Graph 5: Scatter plot of latency vs cost for each placement.
    the RL points should cluster in the bottom-left (low latency, low cost)
    while Kademlia scatters randomly. this is the pareto frontier visualization.
    """
    fig, ax = plt.subplots(figsize=(7, 5))

    rl_lats = [p.get("avg_latency_ms", 0) for p in rl_placements]
    rl_costs = [p.get("total_cost", 0) for p in rl_placements]
    kad_lats = [p.get("avg_latency_ms", 0) for p in kad_placements]
    kad_costs = [p.get("total_cost", 0) for p in kad_placements]

    ax.scatter(rl_lats, rl_costs, c=RL_COLOR, label="DRL Agent", alpha=0.7, s=40, zorder=3)
    ax.scatter(kad_lats, kad_costs, c=KAD_COLOR, label="Kademlia DHT", alpha=0.7, s=40,
               marker="^", zorder=2)

    # shade the ideal region
    if rl_lats and rl_costs:
        ax.axhspan(0, np.median(rl_costs), alpha=0.05, color=ACCENT)
        ax.axvspan(0, np.median(rl_lats), alpha=0.05, color=ACCENT)

    ax.set_xlabel("Average Latency (ms)")
    ax.set_ylabel("Total Cost ($)")
    ax.set_title("Pareto Frontier: Latency vs Cost")
    ax.legend()
    ax.grid(alpha=0.3)

    plt.savefig(os.path.join(output_dir, "05_pareto_frontier.png"))
    plt.close()
    print("  [OK] 05_pareto_frontier.png")


def plot_latency_timeline(rl_placements, kad_placements, output_dir):
    """
    Graph 6: Per-placement latency over time.
    shows the RL agent learning — early placements might be worse,
    but it converges to better latency as it trains.
    """
    fig, ax = plt.subplots(figsize=(9, 4))

    rl_lats = [p.get("avg_latency_ms", 0) for p in rl_placements]
    kad_lats = [p.get("avg_latency_ms", 0) for p in kad_placements]

    ax.plot(range(1, len(rl_lats)+1), rl_lats, color=RL_COLOR, linewidth=1.5,
            label="DRL Agent", alpha=0.8)
    ax.plot(range(1, len(kad_lats)+1), kad_lats, color=KAD_COLOR, linewidth=1.5,
            label="Kademlia DHT", linestyle="--", alpha=0.8)

    # add rolling average to smooth the noise
    if len(rl_lats) >= 5:
        window = min(5, len(rl_lats))
        rl_smooth = np.convolve(rl_lats, np.ones(window)/window, mode="valid")
        ax.plot(range(window, len(rl_lats)+1), rl_smooth, color=RL_COLOR,
                linewidth=2.5, alpha=0.5, label="DRL (smoothed)")

    ax.set_xlabel("Placement Number")
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Per-Placement Latency Over Time (Learning Curve)")
    ax.legend()
    ax.grid(alpha=0.3)

    plt.savefig(os.path.join(output_dir, "06_latency_timeline.png"))
    plt.close()
    print("  [OK] 06_latency_timeline.png")


def plot_uptime_comparison(rl_placements, kad_placements, output_dir):
    """
    Graph 7: Average uptime ratio of nodes selected by each algorithm.
    the RL agent should prefer nodes with higher uptime (reliability objective).
    """
    rl_uptimes = [p.get("avg_uptime", 0) for p in rl_placements]
    kad_uptimes = [p.get("avg_uptime", 0) for p in kad_placements]

    fig, ax = plt.subplots(figsize=(6, 4))

    means = [np.mean(rl_uptimes) if rl_uptimes else 0, np.mean(kad_uptimes) if kad_uptimes else 0]

    bars = ax.bar(["DRL Agent", "Kademlia DHT"], means,
                  color=[RL_COLOR, KAD_COLOR], width=0.5, edgecolor="white")

    for bar, mean in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f"{mean:.2f}", ha="center", va="bottom", fontweight="bold")

    ax.set_ylabel("Average Uptime Ratio")
    ax.set_title("Node Reliability: Selected Node Uptime")
    ax.set_ylim(0, 1.15)
    ax.grid(axis="y", alpha=0.3)

    plt.savefig(os.path.join(output_dir, "07_uptime_comparison.png"))
    plt.close()
    print("  [OK] 07_uptime_comparison.png")


def plot_summary_dashboard(rl_placements, kad_placements, output_dir):
    """
    Graph 8: Combined 2x2 dashboard for the thesis overview figure.
    shows all 4 key metrics in one glance.
    """
    fig = plt.figure(figsize=(12, 9))
    gs = GridSpec(2, 2, figure=fig, hspace=0.35, wspace=0.3)

    rl_lats = [p.get("avg_latency_ms", 0) for p in rl_placements]
    kad_lats = [p.get("avg_latency_ms", 0) for p in kad_placements]
    rl_costs_cum = np.cumsum([p.get("total_cost", 0) for p in rl_placements])
    kad_costs_cum = np.cumsum([p.get("total_cost", 0) for p in kad_placements])
    rl_uptimes = [p.get("avg_uptime", 0) for p in rl_placements]
    kad_uptimes = [p.get("avg_uptime", 0) for p in kad_placements]

    # top-left: latency bar
    ax1 = fig.add_subplot(gs[0, 0])
    means = [np.mean(rl_lats) if rl_lats else 0, np.mean(kad_lats) if kad_lats else 0]
    ax1.bar(["DRL", "Kademlia"], means, color=[RL_COLOR, KAD_COLOR], width=0.5)
    ax1.set_ylabel("Avg Latency (ms)")
    ax1.set_title("(a) Placement Latency")
    ax1.grid(axis="y", alpha=0.3)

    # top-right: cumulative cost
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.plot(range(1, len(rl_costs_cum)+1), rl_costs_cum, color=RL_COLOR, linewidth=2, label="DRL")
    ax2.plot(range(1, len(kad_costs_cum)+1), kad_costs_cum, color=KAD_COLOR, linewidth=2,
             label="Kademlia", linestyle="--")
    ax2.set_xlabel("Placements")
    ax2.set_ylabel("Cumulative Cost ($)")
    ax2.set_title("(b) Cumulative Storage Cost")
    ax2.legend(fontsize=9)
    ax2.grid(alpha=0.3)

    # bottom-left: pareto
    ax3 = fig.add_subplot(gs[1, 0])
    rl_costs_flat = [p.get("total_cost", 0) for p in rl_placements]
    kad_costs_flat = [p.get("total_cost", 0) for p in kad_placements]
    ax3.scatter(rl_lats, rl_costs_flat, c=RL_COLOR, label="DRL", alpha=0.7, s=30)
    ax3.scatter(kad_lats, kad_costs_flat, c=KAD_COLOR, label="Kademlia", alpha=0.7, s=30, marker="^")
    ax3.set_xlabel("Latency (ms)")
    ax3.set_ylabel("Cost ($)")
    ax3.set_title("(c) Pareto Frontier")
    ax3.legend(fontsize=9)
    ax3.grid(alpha=0.3)

    # bottom-right: uptime
    ax4 = fig.add_subplot(gs[1, 1])
    uptime_means = [np.mean(rl_uptimes) if rl_uptimes else 0, np.mean(kad_uptimes) if kad_uptimes else 0]
    ax4.bar(["DRL", "Kademlia"], uptime_means, color=[RL_COLOR, KAD_COLOR], width=0.5)
    ax4.set_ylabel("Avg Node Uptime")
    ax4.set_title("(d) Selected Node Reliability")
    ax4.set_ylim(0, 1.15)
    ax4.grid(axis="y", alpha=0.3)

    fig.suptitle("Multi-Objective DRL Data Placement — Performance Summary", fontsize=14, fontweight="bold")

    plt.savefig(os.path.join(output_dir, "08_summary_dashboard.png"))
    plt.close()
    print("  [OK] 08_summary_dashboard.png")


def main():
    parser = argparse.ArgumentParser(description="GO-DFS DRL Thesis Graph Generator")
    parser.add_argument("--results-dir", default=os.path.join(os.path.dirname(__file__), "results"),
                        help="directory containing rl_metrics.json and kademlia_metrics.json")
    args = parser.parse_args()

    results_dir = args.results_dir
    output_dir = os.path.join(results_dir, "graphs")
    os.makedirs(output_dir, exist_ok=True)

    # load both datasets
    rl_data = load_metrics(results_dir, "rl")
    kad_data = load_metrics(results_dir, "kademlia")

    if not rl_data and not kad_data:
        print("[!] No metrics found. Run benchmark_runner.py first.")
        sys.exit(1)

    rl_placements = extract_placements(rl_data) if rl_data else []
    kad_placements = extract_placements(kad_data) if kad_data else []

    # filter by method to ensure clean data
    rl_only = [p for p in rl_placements if p.get("method") == "rl"]
    kad_only = [p for p in kad_placements if p.get("method") == "kademlia_fallback"]

    # if kademlia run also had some RL placements (sidecar was still up), include fallbacks
    if not kad_only:
        kad_only = kad_placements  # use whatever we got

    print(f"\n  RL placements:       {len(rl_only)}")
    print(f"  Kademlia placements: {len(kad_only)}")
    print(f"  Output directory:    {output_dir}\n")

    if not rl_only and not kad_only:
        print("[!] No placement records found in the metrics files.")
        sys.exit(1)

    # generate all the graphs
    print("Generating thesis graphs...\n")

    plot_avg_latency_comparison(rl_only, kad_only, output_dir)
    plot_cumulative_cost(rl_only, kad_only, output_dir)
    plot_tier_distribution(rl_only, kad_only, output_dir, rl_data, kad_data)
    plot_decision_overhead(rl_only, kad_only, output_dir)
    plot_pareto_frontier(rl_only, kad_only, output_dir)
    plot_latency_timeline(rl_only, kad_only, output_dir)
    plot_uptime_comparison(rl_only, kad_only, output_dir)
    plot_summary_dashboard(rl_only, kad_only, output_dir)

    print(f"\n{'='*50}")
    print(f"  All 8 graphs saved to: {output_dir}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
