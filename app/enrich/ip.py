import ipaddress
from functools import lru_cache
from typing import Optional

from app import config

# Only genuinely internal ranges count as "internal". The documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) used by the sample logs are
# treated as external on purpose, so the demo behaves like real internet traffic.
INTERNAL = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]


def is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in INTERNAL)


@lru_cache(maxsize=1)
def _blocklist() -> frozenset:
    path = config.BLOCKLIST_FILE
    if not path.exists():
        return frozenset()
    lines = (l.strip() for l in path.read_text().splitlines())
    return frozenset(l for l in lines if l and not l.startswith("#"))


@lru_cache(maxsize=512)
def _abuseipdb(ip: str) -> Optional[int]:
    """Optional online lookup. Returns abuse confidence 0-100, or None on any failure."""
    if not (config.ENRICH_ONLINE and config.ABUSEIPDB_API_KEY):
        return None
    try:
        import httpx
        r = httpx.get("https://api.abuseipdb.com/api/v2/check",
                      params={"ipAddress": ip, "maxAgeInDays": 90},
                      headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                      timeout=5)
        r.raise_for_status()
        return int(r.json()["data"]["abuseConfidenceScore"])
    except Exception:
        return None


def enrich_ip(ip: str) -> dict:
    """Read-only reputation check. Safe to expose to the LLM as a tool."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "valid": False}
    internal = is_internal(ip)
    abuse = None if internal else _abuseipdb(ip)
    listed = ip in _blocklist()
    source = "abuseipdb+local" if abuse is not None else "local"
    bad = listed or (abuse is not None and abuse >= 50)
    return {"ip": ip, "valid": True, "internal": internal, "in_local_blocklist": listed,
            "abuse_confidence": abuse, "bad_reputation": bad, "source": source}
