"""Central settings. Thresholds live here so you can tune them in one place."""
import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env", override=True)

# --- detection thresholds ---
BRUTE_THRESHOLD = 8          # failed logins from one IP ...
BRUTE_WINDOW_SEC = 300       # ... inside this many seconds
BRUTE_SUCCESS_GRACE_MIN = 30 # a success this long after the burst still counts
SCAN_PORTS = 15              # distinct destination ports from one IP ...
SCAN_WINDOW_SEC = 60         # ... inside this many seconds
WEB_MIN_HITS = 1             # attack-looking requests before an alert is raised

# --- enrichment ---
BLOCKLIST_FILE = ROOT / "data" / "blocklist.txt"
ENRICH_ONLINE = os.getenv("ENRICH_ONLINE", "0") == "1"   # set to 1 to use AbuseIPDB
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# --- LLM (used from Phase 3) ---
LLM_BASE_URL = "https://openrouter.ai/api/v1"
LLM_MODEL = os.getenv("LLM_MODEL", "anthropic/claude-haiku-4.5")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# --- agent limits (Phase 3) ---
AGENT_MAX_ROUNDS = 8         # maximum tool-calling rounds per alert
AGENT_TIMEOUT_SEC = 120      # wall-clock limit per alert
AGENT_MAX_TOKENS = 40000     # total token ceiling per alert

# --- storage and pipeline (Phase 4) ---
DB_PATH = Path(os.getenv("EMISSARY_DB", str(ROOT / "data" / "emissary.db")))
MAX_ALERTS_PER_RUN = 5             # alerts investigated by the LLM per upload (cost control)
MAX_UPLOAD_BYTES = 5_000_000       # refuse bigger uploads
