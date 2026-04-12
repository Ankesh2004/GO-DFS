package server

import (
	"sync"
	"time"
)

// PlacementMetrics tracks every placement decision and eviction event.
// the thesis benchmarks pull this data to compare RL-enhanced vs baseline Kademlia.
type PlacementMetrics struct {
	mu         sync.Mutex
	placements []PlacementRecord
	evictions  []EvictionRecord
}

// PlacementRecord captures one placement decision for later analysis.
// we log these for both RL and fallback decisions so we can compare.
type PlacementRecord struct {
	Timestamp     time.Time     `json:"timestamp"`
	ChunkKey      string        `json:"chunk_key"`
	Method        string        `json:"method"` // "rl" or "kademlia_fallback"
	SelectedNodes []string      `json:"selected_nodes"`
	SelectedTiers []StorageTier `json:"selected_tiers"`
	AvgLatencyMs  float64       `json:"avg_latency_ms"`
	TotalCost     float64       `json:"total_cost"`
	AvgUptime     float64       `json:"avg_uptime"`
	DurationMs    int64         `json:"duration_ms"` // how long the placement decision took
}

// EvictionRecord captures when a node dies and how much data was at risk.
// high eviction counts = the RL agent isn't learning fast enough.
type EvictionRecord struct {
	Timestamp     time.Time `json:"timestamp"`
	EvictedAddr   string    `json:"evicted_addr"`
	UptimeAtDeath float64   `json:"uptime_at_death"`
	ChunksOnNode  int       `json:"chunks_on_node"`
}

// NewPlacementMetrics creates a fresh metrics tracker.
func NewPlacementMetrics() *PlacementMetrics {
	return &PlacementMetrics{}
}

// RecordPlacement logs a placement decision.
func (pm *PlacementMetrics) RecordPlacement(record PlacementRecord) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.placements = append(pm.placements, record)
}

// RecordEviction logs a node death.
func (pm *PlacementMetrics) RecordEviction(record EvictionRecord) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.evictions = append(pm.evictions, record)
}

// GetPlacements returns a copy of all placement records.
func (pm *PlacementMetrics) GetPlacements() []PlacementRecord {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	result := make([]PlacementRecord, len(pm.placements))
	copy(result, pm.placements)
	return result
}

// GetEvictions returns a copy of all eviction records.
func (pm *PlacementMetrics) GetEvictions() []EvictionRecord {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	result := make([]EvictionRecord, len(pm.evictions))
	copy(result, pm.evictions)
	return result
}

// Summary returns high-level metrics for the /api/status response.
func (pm *PlacementMetrics) Summary() map[string]any {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	rlCount := 0
	fallbackCount := 0
	for _, p := range pm.placements {
		if p.Method == "rl" {
			rlCount++
		} else {
			fallbackCount++
		}
	}

	return map[string]any{
		"total_placements":    len(pm.placements),
		"rl_placements":       rlCount,
		"fallback_placements": fallbackCount,
		"total_evictions":     len(pm.evictions),
	}
}
