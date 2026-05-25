# BBAT v3.1.0 — Surgical Upgrade Changelog

## 🔒 Stealth
- **User-Agent rotation** added to `utils.py` via a curated pool of 10 realistic browser UAs.
- All modules that perform HTTP requests now pull a random UA per call (`get_random_ua()`).
- Old static `BBAT/1.0` headers removed across the entire codebase.

## ⚡ Performance
- Replaced `requests` with **`httpx`** across all I/O-heavy modules (`git_scanner`, `s3_scanner`, `takeover`, `waf_detector`, `recon`, `async_engine`).
- `AsyncEngine` now uses `httpx.AsyncClient` with HTTP/2 support and a bounded semaphore (100 default, configurable).
- Added **jitter** (random delay 0–500 ms) to async fetches to evade WAF rate-limiting.
- `recon.py` now defaults to `dns.resolver` (non-blocking iterator, faster than `socket.gethostbyname`).

## 🛡️ Stability
- Replaced all hardcoded `verify=False` calls with a **configurable `ssl_verify` toggle** in `config.json`.
- Modules read this setting from their config payload and pass it to `httpx.get(..., verify=ssl_verify)`.

## 🎯 Accuracy
- **`takeover.py`** — Replaced naive 404 detection with **Provider-Specific Fingerprint Verification**. 
  - Maps 30+ cloud services to known error-page body signatures (e.g., `NoSuchBucket`, `There isn't a GitHub Pages site here.`).
  - A finding is only logged if the response body matches the service's unique fingerprint.
- **`waf_detector.py`** — Added **Active Probing**.
  - Sends benign-but-suspicious payloads (`/?id=' OR 1=1`, `<eval>alert(1)</eval>`) and compares status codes / response bodies.
  - Provides both passive header-based detection and active confirmation.
- **`nuclei_scanner.py`** — Added **strict subprocess input sanitization** via regex validators (`_SAFE_TARGET_RE`, `_SAFE_PATH_RE`, `_SAFE_INT_RE`) to prevent command injection.

## 🏗 Architecture
- **`db.py`** — New lightweight **SQLite** backend layer to replace raw JSON accumulation.
  - Prevents memory crashes on large-scale scans.
  - Tables: `targets`, `subdomains`, `findings`, `endpoints`, `technologies`, `ports`, `dns_records`.
- **`report.py`** — Migrated to read aggregated stats from the SQLite DB instead of loading every JSON file into memory.
- **`dashboard.py`** — Migrated to query the SQLite backend for real-time stats / findings / endpoints, with paginated reads.
- All modules remain **decoupled** and follow the existing modular structure with zero circular imports.

## 📦 Dependencies
- Added `httpx>=0.25.0` (async HTTP client, replaces `requests`).
- Added `dnspython>=2.4.2` (fast DNS resolution).
- Retained `flask`, `beautifulsoup4`, `python-whois`, `colorama`.
