from dataclasses import dataclass


@dataclass
class Config:
    # --- Target (the AI you attack) ---
    target_url: str = "http://127.0.0.1:8000"
    predict_path: str = "/predict"
    timeout_s: float = 10.0

    # --- Runner ---
    concurrency: int = 8

    # --- Flip hunter (sensitivity probe) ---
    query_budget: int = 200          # max endpoint calls per seed, per hunt

    # --- Semantic gate ---
    semantic_model: str = "all-MiniLM-L6-v2"
    semantic_tau: float = 0.85       # min cosine similarity for a flip to be "real"

    # --- Metamorphic oracle (invariance probe) ---
    conf_drift_threshold: float = 0.15  # confidence swing that counts as silent degradation

    # --- Severity ---
    latency_flag_ms: float = 1000.0     # responses slower than this are flagged (sponge/DoS)

    # --- Output ---
    db_path: str = "results.db"
    report_path: str = "report.html"
