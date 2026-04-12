package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PlacementOptimizer talks to the Python RL sidecar to get intelligent
// placement decisions. if the sidecar is down or not configured, every
// method gracefully falls back so normal Kademlia routing still works.
type PlacementOptimizer struct {
	sidecarURL string
	client     *http.Client
	enabled    bool
}

// NewPlacementOptimizer creates an optimizer instance.
// pass an empty URL to disable RL placement entirely.
func NewPlacementOptimizer(sidecarURL string) *PlacementOptimizer {
	return &PlacementOptimizer{
		sidecarURL: sidecarURL,
		client: &http.Client{
			Timeout: 2 * time.Second, // don't let the sidecar slow down placements
		},
		enabled: sidecarURL != "",
	}
}

// NodeCandidate bundles a DHT node with its full profile for the optimizer.
// sent to the sidecar so it has everything it needs to score candidates.
type NodeCandidate struct {
	Addr    string
	Profile StorageProfile
}

// candidateJSON is the wire format for sending candidates to the sidecar.
// kept separate from NodeCandidate to avoid leaking internal Go types into the API.
type candidateJSON struct {
	Addr          string  `json:"addr"`
	Tier          int     `json:"tier"`
	LatencyMs     float64 `json:"latency_ms"`
	CostPerGBHour float64 `json:"cost_per_gb_hour"`
	AvailableMB   int64   `json:"available_mb"`
	BandwidthMbps float64 `json:"bandwidth_mbps"`
	UptimeRatio   float64 `json:"uptime_ratio"`
	AvgSessionSec int64   `json:"avg_session_sec"`
	HeartbeatRTT  float64 `json:"heartbeat_rtt_ms"`
}

type placementRequest struct {
	Candidates []candidateJSON `json:"candidates"`
	ChunkSize  int64           `json:"chunk_size"`
	Needed     int             `json:"needed"`
}

type placementResponse struct {
	Targets     []string `json:"targets"`
	PlacementID string   `json:"placement_id"`
}

// SelectOptimalNodes sends K candidates to the RL sidecar and gets back
// the best R nodes for this specific chunk. returns the selected addresses,
// a placement ID for tracking outcomes, and any error.
// if the sidecar is unreachable, returns an error so the caller can fall back.
func (po *PlacementOptimizer) SelectOptimalNodes(
	candidates []NodeCandidate,
	chunkSize int64,
	needed int,
) ([]string, string, error) {
	if !po.enabled || len(candidates) == 0 {
		return nil, "", fmt.Errorf("RL optimizer disabled or no candidates")
	}

	// convert to wire format
	cands := make([]candidateJSON, len(candidates))
	for i, c := range candidates {
		cands[i] = candidateJSON{
			Addr:          c.Addr,
			Tier:          int(c.Profile.Tier),
			LatencyMs:     c.Profile.LatencyMs,
			CostPerGBHour: c.Profile.CostPerGBHour,
			AvailableMB:   c.Profile.AvailableMB,
			BandwidthMbps: c.Profile.BandwidthMbps,
			UptimeRatio:   c.Profile.UptimeRatio,
			AvgSessionSec: c.Profile.AvgSessionSec,
			HeartbeatRTT:  c.Profile.HeartbeatRTTMs,
		}
	}

	body, err := json.Marshal(placementRequest{
		Candidates: cands,
		ChunkSize:  chunkSize,
		Needed:     needed,
	})
	if err != nil {
		return nil, "", fmt.Errorf("marshal placement request: %w", err)
	}

	resp, err := po.client.Post(po.sidecarURL+"/optimize_placement", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("sidecar returned status %d", resp.StatusCode)
	}

	var result placementResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", fmt.Errorf("decode sidecar response: %w", err)
	}

	return result.Targets, result.PlacementID, nil
}

// RecordOutcome reports the result of a placement back to the RL agent
// so it can learn from real network conditions. called after pushing chunks.
func (po *PlacementOptimizer) RecordOutcome(placementID string, actualLatencyMs float64, success bool) error {
	if !po.enabled || placementID == "" {
		return nil
	}

	payload := map[string]any{
		"placement_id":   placementID,
		"actual_latency": actualLatencyMs,
		"success":        success,
	}
	body, _ := json.Marshal(payload)

	resp, err := po.client.Post(po.sidecarURL+"/record_outcome", "application/json", bytes.NewReader(body))
	if err != nil {
		return err // don't blow up, this is best-effort
	}
	resp.Body.Close()
	return nil
}

// RecordEviction tells the RL agent that a node just died.
// the sidecar will apply a massive negative reward (-100) to all recent
// placements that targeted the evicted address. this is how the agent
// learns to avoid flaky peers even if their hardware looks amazing.
func (po *PlacementOptimizer) RecordEviction(evictedAddr string) error {
	if !po.enabled {
		return nil
	}

	payload := map[string]any{
		"evicted_addr": evictedAddr,
	}
	body, _ := json.Marshal(payload)

	resp, err := po.client.Post(po.sidecarURL+"/record_eviction", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// RecordRTT sends heartbeat round-trip measurements to the sidecar for trust calibration.
// the sidecar compares RTT against the node's self-reported LatencyMs to compute
// a trust divergence score. if the divergence is high, the agent penalizes that node.
func (po *PlacementOptimizer) RecordRTT(addr string, avgRTTMs float64) error {
	if !po.enabled {
		return nil
	}

	// look up the node's claimed latency so the sidecar can compute divergence.
	// we send both values and let the Python side do the math.
	payload := map[string]any{
		"addr":             addr,
		"heartbeat_rtt_ms": avgRTTMs,
	}
	body, _ := json.Marshal(payload)

	resp, err := po.client.Post(po.sidecarURL+"/calibrate_trust", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// defaultProfile returns a conservative SSD-tier profile for nodes
// we haven't received a PeerExchange from yet. the 0.5 uptime
// means the RL agent won't aggressively prefer or avoid unknown nodes.
func defaultProfile() StorageProfile {
	return StorageProfile{
		Tier:          TierSSD,
		LatencyMs:     5.0,
		CostPerGBHour: 0.01,
		AvailableMB:   10240, // assume 10GB free
		BandwidthMbps: 100.0,
		UptimeRatio:   0.5,
		AvgSessionSec: 0,
	}
}

// buildCandidateProfile merges the static hardware profile (from PeerExchange)
// with live reliability stats (from heartbeat tracking) into a single profile
// for the RL agent. unknown peers get a safe default.
func (s *FileServer) buildCandidateProfile(addr string) StorageProfile {
	// grab hardware profile from what they told us during PeerExchange
	s.peerProfilesLock.RLock()
	profile, hasProfile := s.peerProfiles[addr]
	s.peerProfilesLock.RUnlock()
	if !hasProfile {
		profile = defaultProfile()
	}

	// overlay live reliability + RTT calibration from heartbeat history.
	// these fields are computed from OUR observations, not self-reported.
	s.healthLock.Lock()
	if health, ok := s.peerHealth[addr]; ok {
		profile.UptimeRatio = health.UptimeRatio()
		profile.AvgSessionSec = health.AvgSessionLength()
		profile.HeartbeatRTTMs = health.AvgRTTMs
	}
	s.healthLock.Unlock()

	return profile
}
