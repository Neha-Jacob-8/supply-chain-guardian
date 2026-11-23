"""Load KEY=VALUE pairs from a local .env file into the environment (existing variables win)."""
import os
from pathlib import Path


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
