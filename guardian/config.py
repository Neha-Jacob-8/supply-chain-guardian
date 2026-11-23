"""Load KEY=VALUE pairs from a local .env file into the environment (existing variables win)."""
import os
import time
from pathlib import Path


def cache_ttl_seconds():
    """Online intelligence cache lifetime; offline mode always permits stale replay."""
    try:
        return max(0, int(os.environ.get("GUARDIAN_CACHE_TTL_SECONDS", "86400")))
    except ValueError:
        return 86400


def cache_is_fresh(path, ttl=None):
    path = Path(path)
    if not path.is_file():
        return False
    ttl = cache_ttl_seconds() if ttl is None else ttl
    return ttl == 0 or time.time() - path.stat().st_mtime <= ttl


def load_dotenv(path=".env"):
    p = Path(path)
    if not p.is_file():
        return 0
    n = 0
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and v and k not in os.environ:
            os.environ[k] = v
            n += 1
    return n
