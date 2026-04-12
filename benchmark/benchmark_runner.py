"""
benchmark_runner.py — runs the full RL vs Kademlia comparison for the thesis.

two phases:
  phase 1: upload N files with RL enabled (sidecar running)
  phase 2: upload N files with RL disabled (sidecar stopped / --rl-enabled off)

collects metrics from /api/metrics after each phase and dumps them
to JSON for the plotter script. run this AFTER the nodes are already up.

usage:
  python benchmark\benchmark_runner.py --mode rl --count 30
  python benchmark\benchmark_runner.py --mode kademlia --count 30
  python benchmark\benchmark_runner.py --mode both --count 30
"""

import argparse
import json
import os
import random
import string
import time
import requests
import sys

API_BASE = "http://127.0.0.1:9001"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "results")


def get_token(data_dir):
    """read the API auth token from the node's data directory."""
    token_path = os.path.join(data_dir, "api_token")
    if not os.path.exists(token_path):
        print(f"[!] Token file not found at {token_path}")
        sys.exit(1)
    with open(token_path, "r") as f:
        return f.read().strip()


def upload_file(token, file_content, filename):
    """push a file into the mesh via the control API."""
    headers = {"X-Local-Auth": token}
    files = {"file": (filename, file_content)}
    try:
        resp = requests.post(f"{API_BASE}/api/put", headers=headers, files=files, timeout=10)
        return resp.json()
    except Exception as e:
        print(f"  [!] Upload failed: {e}")
        return None


def fetch_metrics(token):
    """pull placement metrics from the node."""
    headers = {"X-Local-Auth": token}
    try:
        resp = requests.get(f"{API_BASE}/api/metrics", headers=headers, timeout=5)
        return resp.json()
    except Exception as e:
        print(f"  [!] Metrics fetch failed: {e}")
        return None


def generate_random_file(size_kb):
    """make a random file of the given size. varying sizes stress the chunker."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024))


def run_benchmark(token, count, label):
    """upload count files with varying sizes and collect metrics."""
    print(f"\n{'='*50}")
    print(f"  Running benchmark: {label} ({count} files)")
    print(f"{'='*50}")

    # file sizes to test — small, medium, larger chunks
    sizes_kb = [1, 4, 16, 64, 128, 256]

    for i in range(count):
        size = random.choice(sizes_kb)
        filename = f"bench_{label}_{i:04d}_{size}kb.dat"
        content = generate_random_file(size)

        result = upload_file(token, content, filename)
        if result and "cid" in result:
            print(f"  [{i+1}/{count}] {filename} -> CID: {result['cid'][:16]}...")
        else:
            print(f"  [{i+1}/{count}] {filename} -> FAILED")

        # small delay so the heartbeat/RTT system gets some cycles
        time.sleep(0.3)

    # fetch final metrics
    print(f"\n  Fetching metrics for {label}...")
    metrics = fetch_metrics(token)
    return metrics


def save_results(metrics, label):
    """dump the metrics to a JSON file for the plotter."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"{label}_metrics.json")
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Saved to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="GO-DFS DRL Benchmark Runner")
    parser.add_argument("--mode", choices=["rl", "kademlia", "both"], default="both",
                        help="which mode to benchmark")
    parser.add_argument("--count", type=int, default=30,
                        help="number of files to upload per phase")
    parser.add_argument("--data-dir", default="cas_test_1",
                        help="path to the node's data directory for the API token")
    parser.add_argument("--api", default="http://127.0.0.1:9001",
                        help="API base URL for the target node")
    args = parser.parse_args()

    global API_BASE
    API_BASE = args.api

    token = get_token(args.data_dir)

    if args.mode in ("rl", "both"):
        print("\n[Phase 1] RL-enabled benchmark")
        print("  Make sure the RL sidecar is running (python rl_sidecar/server.py)")
        print("  Make sure nodes were started with --rl-enabled")
        input("  Press Enter when ready...")

        metrics = run_benchmark(token, args.count, "rl")
        if metrics:
            save_results(metrics, "rl")

    if args.mode in ("kademlia", "both"):
        print("\n[Phase 2] Kademlia-only benchmark")
        print("  STOP the RL sidecar (Ctrl+C in its terminal)")
        print("  This forces all placements to use kademlia_fallback")
        input("  Press Enter when the sidecar is stopped...")

        metrics = run_benchmark(token, args.count, "kademlia")
        if metrics:
            save_results(metrics, "kademlia")

    print("\n" + "="*50)
    print("  Benchmark complete!")
    print(f"  Results saved to: {OUTPUT_DIR}")
    print(f"  Now run: python benchmark\\plot_results.py")
    print("="*50)


if __name__ == "__main__":
    main()
