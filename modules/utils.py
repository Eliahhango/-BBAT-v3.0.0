"""
Utility helpers for BBAT.
"""

import json
import os
from datetime import datetime
from urllib.parse import urlparse


def load_config(path: str) -> dict:
    """Load JSON configuration file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_results(data: dict, filepath: str):
    """Save results to JSON file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


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
    import re
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
    print("         [ Bug Bounty Automation Toolkit v1.0.0 ]")
    print("         [ For Authorized Bug Bounty Programs Only ]")
    print()
