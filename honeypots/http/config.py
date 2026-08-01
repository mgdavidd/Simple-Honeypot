import os
import json
from common.brute_force_guard import BruteForceGuard
from common.rate_limit_guard import RateLimitGuard
from common.ip_blocker import IPBlocker

# ── Identidad del servicio ────────────────────────────────────────────────────
SERVICE_TYPE = os.getenv("SERVICE_TYPE", "http")
REPLICA_ID   = os.getenv("REPLICA_ID", "1")
SERVICE_ID   = f"{SERVICE_TYPE}-{REPLICA_ID}"
TEMPLATE     = os.getenv("CONFIG_TEMPLATE", "wordpress")

# ── Parámetros de protección ──────────────────────────────────────────────────
ENABLE_RATE_LIMIT      = os.getenv("CONFIG_ENABLE_RATE_LIMIT", "true").lower() == "true"
RATE_LIMIT_THRESHOLD   = int(os.getenv("CONFIG_RATE_LIMIT_THRESHOLD", "30"))
RATE_LIMIT_WINDOW      = int(os.getenv("CONFIG_RATE_LIMIT_WINDOW", "15"))
BAN_SECONDS            = int(os.getenv("CONFIG_BAN_SECONDS", "600"))
FAILED_THRESHOLD       = int(os.getenv("CONFIG_FAILED_THRESHOLD", "20"))

# ── Credenciales válidas ──────────────────────────────────────────────────────
try:
    VALID_CREDENTIALS: dict = json.loads(os.getenv("CONFIG_VALID_CREDENTIALS", "{}"))
except json.JSONDecodeError:
    VALID_CREDENTIALS = {}

# ── Guardias ──────────────────────────────────────────────────────────────────
blocker = IPBlocker()

brute_force_guard = BruteForceGuard(service_id=SERVICE_ID, blocker=blocker)
brute_force_guard.FAILED_THRESHOLD = FAILED_THRESHOLD
brute_force_guard.BAN_SECONDS      = BAN_SECONDS

rate_limit_guard = None
if ENABLE_RATE_LIMIT:
    rate_limit_guard = RateLimitGuard(service_id=SERVICE_ID, blocker=blocker)
    rate_limit_guard.REQUEST_THRESHOLD = RATE_LIMIT_THRESHOLD
    rate_limit_guard.WINDOW_SECONDS    = RATE_LIMIT_WINDOW
    rate_limit_guard.BAN_SECONDS       = BAN_SECONDS

# ── Diagnóstico al arranque ───────────────────────────────────────────────────
def print_startup_info() -> None:
    print(f"[http] {SERVICE_ID} iniciado")
    print(f"  Template: {TEMPLATE}")
    print(f"  Rate Limit: {'ENABLED' if ENABLE_RATE_LIMIT else 'DISABLED'}")
    if ENABLE_RATE_LIMIT:
        print(f"    - Threshold: {RATE_LIMIT_THRESHOLD} GETs en {RATE_LIMIT_WINDOW}s")
    print(f"  Brute Force Threshold: {FAILED_THRESHOLD} intentos")
    print(f"  Ban Duration: {BAN_SECONDS}s")
    if VALID_CREDENTIALS:
        print(f"  Valid Credentials: {VALID_CREDENTIALS.get('username', 'N/A')}")