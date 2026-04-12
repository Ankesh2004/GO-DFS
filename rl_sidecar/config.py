# hyperparameters and reward weights for the DDPG placement agent.
# tweak these to shift the RL agent's priorities between latency, cost, and reliability.

# ---- reward function weights ----
# R_immediate = -w1*latency - w2*cost - w3*P_fail + w4*capacity_margin
# R_trust     = -w5*trust_divergence
# R_eviction  = -EVICTION_PENALTY  (retroactive)
W_LATENCY = 1.0
W_COST = 0.5
W_RELIABILITY = 2.0   # cranked up because churn is the killer in P2P
W_CAPACITY = 0.1
W_TRUST = 1.5          # penalize nodes whose RTT diverges from claimed latency

EVICTION_PENALTY = 100.0  # massive negative reward when a node dies

# ---- DDPG hyperparameters ----
ACTOR_LR = 1e-4
CRITIC_LR = 1e-3
GAMMA = 0.99              # discount factor
TAU = 0.005               # soft update rate for target networks
BATCH_SIZE = 64
REPLAY_BUFFER_SIZE = 100000
WARMUP_STEPS = 500        # random actions before the agent starts learning

# ---- network architecture ----
HIDDEN_DIM = 128          # hidden layer size for both actor and critic
NUM_HIDDEN_LAYERS = 2

# ---- candidate features ----
# per-candidate feature vector: [latency, cost, available_mb, bandwidth,
#   tier_nvme, tier_ssd, tier_hdd, uptime_ratio, avg_session_sec,
#   heartbeat_rtt, trust_divergence]
FEATURES_PER_CANDIDATE = 11
MAX_CANDIDATES = 20       # K value from Kademlia

# ---- placement history ----
# how many recent placements to keep for retroactive eviction penalties
PLACEMENT_HISTORY_SIZE = 1000

# ---- exploration noise ----
NOISE_SIGMA = 0.2         # Ornstein-Uhlenbeck noise sigma
NOISE_THETA = 0.15        # OU noise theta (mean reversion speed)
