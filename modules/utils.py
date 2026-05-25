"""
Utility helpers for BBAT.
All paths resolve absolutely via BBAT_BASE_DIR env var or __file__ fallback.
"""

import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse
import random

# ─── Absolute Base Directory ────────────────────────────────────────
BBAT_BASE_DIR = os.environ.get("BBAT_BASE_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.0.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
]


def load_config(path: str) -> dict:
    """Load JSON configuration file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_results(data: dict, filepath: str):
    """Save results to JSON file (backward compatibility)."""
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def get_random_ua() -> str:
    """Return a random, realistic User-Agent string."""
    return random.choice(USER_AGENTS)


def load_wordlist(path: str) -> list:
    """Load a wordlist file into a list of strings."""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def is_valid_url(url: str) -> bool:
    """Check if a URL is valid."""
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def normalize_url(url: str) -> str:
    """Normalize URL (ensure scheme)."""
    if not url.startswith(("http://", "https://")):
        return f"http://{url}"
    return url


def get_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(normalize_url(url))
    return parsed.netloc


def sanitize_filename(name: str) -> str:
    """Sanitize a string for safe use as a filename."""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)


def timestamp() -> str:
    """Return current ISO timestamp."""
    return datetime.utcnow().isoformat() + "Z"


def banner():
    """Print BBAT banner."""
    print(r"""
  ____  ____   ____              _           _   _             _
 |  _ \| __ ) / ___|_ __ ___  __| |_   _ ___| |_(_)_ __   __ _| |
 | |_) |  _ \| |   | '__/ _ \/ _` | | | / __| __| | '_ \ / _` | |
 |  __/| |_) | |___| | |  __/ (_| | |_| \__ \ |_| | | | | (_| | |
 |_|   |____/ \____|_|  \___|\__,_|\__,_|___/\__|_|_| |_|\__,_|_|
    """)
    print("         [ Bug Bounty Automation Toolkit v3.1.0 ]")
    print("         [ For Authorized Bug Bounty Programs Only ]")
    print()
