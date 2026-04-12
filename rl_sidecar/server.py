"""
RL Placement Sidecar — Flask API server.

runs alongside each Go node on localhost:5100.
the Go node sends placement queries here, and we return the optimal
R nodes from the K candidates using a DDPG agent.

endpoints:
  POST /optimize_placement  — pick best R nodes from K candidates
  POST /record_outcome      — report how a placement actually went
  POST /record_eviction     — a node died, apply penalty to past placements
  POST /calibrate_trust     — heartbeat RTT data for trust scoring
  GET  /health              — quick status check
"""

import os
import sys
import logging
from flask import Flask, request, jsonify

from agent import DDPGAgent

# keep flask quiet unless something breaks
logging.getLogger("werkzeug").setLevel(logging.WARNING)

app = Flask(__name__)
agent = DDPGAgent()

# counters for the /health endpoint
eviction_penalties_total = 0
trust_calibrations_total = 0


@app.route("/optimize_placement", methods=["POST"])
def optimize_placement():
    """
    input:  { candidates: [{addr, latency_ms, cost_per_gb_hour, ...}], chunk_size, needed }
    output: { targets: [addr1, addr2, ...], placement_id: "abc123" }
    """
    data = request.get_json(force=True)
    candidates = data.get("candidates", [])
    needed = data.get("needed", 3)

    if not candidates:
        return jsonify({"error": "no candidates provided"}), 400

    targets, placement_id = agent.select_targets(candidates, needed)

    return jsonify({
        "targets": targets,
        "placement_id": placement_id,
    })


@app.route("/record_outcome", methods=["POST"])
def record_outcome():
    """
    the Go node tells us how a placement went — actual latency and success/failure.
    we use this for retroactive reward correction.
    """
    data = request.get_json(force=True)
    placement_id = data.get("placement_id", "")
    actual_latency = data.get("actual_latency", 0.0)
    success = data.get("success", True)

    agent.record_outcome(placement_id, actual_latency, success)
    return jsonify({"status": "ok"})


@app.route("/record_eviction", methods=["POST"])
def record_eviction():
    """
    a node just died. we walk back through recent placement history
    and apply a massive negative reward to every placement that
    targeted the dead node. this is how the agent learns to avoid flaky peers.
    """
    global eviction_penalties_total

    data = request.get_json(force=True)
    evicted_addr = data.get("evicted_addr", "")

    if not evicted_addr:
        return jsonify({"error": "evicted_addr required"}), 400

    penalties = agent.record_eviction(evicted_addr)
    eviction_penalties_total += penalties

    print(f"[RL] Eviction penalty for {evicted_addr}: {penalties} placements penalized")
    return jsonify({"status": "ok", "penalties_applied": penalties})


@app.route("/calibrate_trust", methods=["POST"])
def calibrate_trust():
    """
    heartbeat RTT data comes in here. we compare the observed RTT against
    the node's self-reported latency to compute a trust divergence score.
    high divergence = the node is lying or degraded.
    """
    global trust_calibrations_total

    data = request.get_json(force=True)
    addr = data.get("addr", "")
    heartbeat_rtt = data.get("heartbeat_rtt_ms", 0.0)
    # claimed latency comes from the profile — we look it up if not provided
    claimed_latency = data.get("claimed_latency_ms", heartbeat_rtt)

    divergence = agent.calibrate_trust(addr, claimed_latency, heartbeat_rtt)
    trust_calibrations_total += 1

    return jsonify({"status": "ok", "divergence": round(divergence, 4)})


@app.route("/health", methods=["GET"])
def health():
    """quick status check — the Go node polls this to verify the sidecar is alive."""
    stats = agent.get_stats()
    return jsonify({
        "status": "ok",
        "model_version": stats["model_version"],
        "total_placements": stats["total_steps"],
        "eviction_penalties_applied": eviction_penalties_total,
        "trust_calibrations": trust_calibrations_total,
        "replay_buffer_size": stats["replay_buffer_size"],
        "warmup_remaining": stats["warmup_remaining"],
    })


if __name__ == "__main__":
    port = int(os.environ.get("RL_PORT", 5100))
    print(f"[RL Sidecar] Starting on port {port}")
    print(f"[RL Sidecar] Features per candidate: {agent.max_candidates * 11}")
    print(f"[RL Sidecar] Warmup steps: {agent.total_steps}/{500}")
    app.run(host="127.0.0.1", port=port, debug=False)
