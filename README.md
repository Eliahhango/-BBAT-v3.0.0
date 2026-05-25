# 🐛 BBAT - Bug Bounty Automation Toolkit v3.0.0

**Repository:** https://github.com/Eliahhango/-BBAT-v3.0.0

A modular, extensible Python framework for **authorized** bug bounty reconnaissance, vulnerability detection, and reporting.

> ⚠️ **Disclaimer:** This tool is intended solely for security research on systems you own or have explicit written authorization to test (e.g., bug bounty programs, penetration testing engagements). Unauthorized access to computer systems is illegal.

---

## 🚀 Features

### Core Modules
- **Reconnaissance** – Subdomain enumeration, DNS resolution, port scanning, WHOIS lookup
- **Crawler** – Recursive web crawling with form and comment extraction
- **Fuzzer** – Directory/file brute-forcing with custom wordlists
- **Scanner** – Security header checks, CORS misconfiguration, open redirect detection
- **Parser** – Result parser, data extractor, and Markdown report generator

### Advanced Recon
- **CTLog** – Certificate Transparency log enumeration via crt.sh
- **Subdomain Takeover** – Detect dangling CNAMEs for 40+ cloud services
- **JS Analyzer** – Extract hidden endpoints and secrets (API keys, JWTs, tokens) from JavaScript
- **Fingerprint** – Web technology fingerprinting (50+ technologies)
- **Wayback** – Historical URL discovery from archive.org
- **S3 Scanner** – Public S3 bucket enumeration
- **Git Scanner** – Exposed `.git`, `.env`, `.svn`, and other sensitive path detection

### Specialized Scanners
- **Nuclei Scanner** – CVE and template-based vulnerability scanning via ProjectDiscovery Nuclei
- **WAF Detector** – Identify 30+ Web Application Firewalls and CDNs
- **API Fuzzer** – Discover REST/GraphQL endpoints and test for IDOR/reflection
- **ParamFinder** – Common parameter injection and reflection testing

### Performance & Automation
- **Async Engine** – High-speed concurrent HTTP engine using `aiohttp` (100+ concurrent requests)
- **Screenshot** – Headless browser screenshot capture (Playwright/Selenium)
- **Notifier** – Slack and Discord webhook notifications for critical/high findings
- **Report Generator** – Automatic Markdown and HTML report generation
- **Dashboard** – Flask-based interactive HTML dashboard (http://127.0.0.1:5000)
- **Docker** – Full Dockerfile for containerized deployment

---

## 📦 Installation

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/Eliahhango/-BBAT-v3.0.0.git
cd -BBAT-v3.0.0

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install core dependencies
pip install -r requirements.txt
```

### Optional Dependencies

```bash
# For async high-speed scanning
pip install aiohttp

# For screenshot module
pip install playwright && playwright install chromium
# OR
pip install selenium

# For dashboard
pip install flask

# For DNS resolution (improved over socket)
pip install dnspython

# For WHOIS lookups
pip install python-whois

# For Nuclei integration (requires nuclei binary)
# Install: https://github.com/projectdiscovery/nuclei
```

### Docker Installation

```bash
# Build the image
docker build -t bbat .

# Run a single scan
docker run --rm -v $(pwd)/output:/app/output bbat full example.com

# Run the dashboard
docker run --rm -p 5000:5000 -v $(pwd)/output:/app/output bbat dashboard
```

---

## 🛠️ CLI Usage

### Individual Commands

```bash
# Reconnaissance
python main.py recon example.com

# Vulnerability scan
python main.py scan https://example.com

# Directory fuzzing
python main.py fuzz https://example.com

# Web crawling
python main.py crawl https://example.com

# Subdomain takeover detection
python main.py takeover example.com

# JavaScript analysis (pass file with .js URLs)
python main.py js_analyze js_urls.txt

# Technology fingerprinting
python main.py fingerprint https://example.com

# Certificate Transparency logs
python main.py ctlog example.com

# Wayback Machine URLs
python main.py wayback example.com

# S3 bucket scan
python main.py s3 example.com

# Exposed repository scan
python main.py gitscan https://example.com

# Nuclei CVE/template scan
python main.py nuclei https://example.com

# Capture screenshots (pass file with URLs)
python main.py screenshot urls.txt

# WAF/CDN detection
python main.py waf https://example.com

# API endpoint fuzzing
python main.py api_fuzz https://api.example.com
```

### Dashboard

```bash
# Launch the Flask web dashboard
python main.py dashboard

# Custom host/port
python main.py dashboard --host 0.0.0.0 --port 8080
```

### Full Pipeline

Run the complete automated workflow:

```bash
python main.py full example.com
```

This executes:
1. Reconnaissance (subdomains, DNS, ports, WHOIS)
2. Certificate Transparency log query
3. Wayback Machine URL discovery
4. Web crawling
5. Directory fuzzing
6. Vulnerability scanning
7. Subdomain takeover detection
8. S3 bucket enumeration
9. Exposed repo/file scan
10. Technology fingerprinting
11. Report generation (Markdown + HTML)

---

## 📁 Project Structure

```
bbat/
├── main.py                    # CLI entry point
├── config.json                # Global configuration
├── config_test.json           # Test configuration (small limits)
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Docker image definition
├── README.md                  # This file
├── wordlists/
│   ├── common.txt             # Default wordlist
│   └── test.txt               # Small test wordlist
└── modules/
    ├── __init__.py
    ├── utils.py               # Shared utilities (config, save, sanitize)
    ├── async_engine.py        # High-speed async HTTP engine
    ├── recon.py               # Reconnaissance (subdomains, DNS, ports, WHOIS)
    ├── crawler.py             # Web crawler with form extraction
    ├── fuzzer.py              # Directory/file brute-forcer
    ├── scanner.py             # Vulnerability scanner (headers, CORS, redirects)
    ├── parser.py              # Result parser & data extractor
    ├── ctlog.py               # Certificate Transparency logs
    ├── takeover.py            # Subdomain takeover detection (40+ signatures)
    ├── js_analyzer.py         # JS endpoint/secret extraction
    ├── fingerprint.py         # Technology fingerprinting (50+ techs)
    ├── wayback.py             # Internet Archive URL discovery
    ├── s3_scanner.py          # Public S3 bucket enumeration
    ├── git_scanner.py         # Exposed source control detection
    ├── nuclei_scanner.py      # ProjectDiscovery Nuclei integration
    ├── screenshot.py          # Headless browser screenshots
    ├── waf_detector.py        # WAF/CDN fingerprinting (30+ WAFs)
    ├── api_fuzzer.py          # REST/GraphQL discovery & IDOR testing
    ├── paramfinder.py         # Parameter injection testing
    ├── notifier.py            # Slack/Discord webhook alerts
    ├── report.py              # Markdown/HTML report generator
    └── dashboard.py           # Flask-based HTML dashboard
```

---

## ⚙️ Configuration

Edit `config.json` to customize:

- **Thread counts**, timeouts, and user agents
- **Port scanning** range and rate limits
- **Crawler** depth and page limits
- **Fuzzer** extensions and HTTP methods
- **Notifier** webhook URLs and severity thresholds
- **Nuclei** templates directory, severity filter, rate limits
- **Screenshot** resolution, output directory, backend
- **Dashboard** host and port
- **Async engine** concurrency limits
- **Report** output formats (JSON, Markdown, HTML)

---

## 🔒 Responsible Disclosure

Always follow responsible disclosure practices:
1. Only test systems you own or have **explicit authorization** to test.
2. Respect rate limits and do not cause denial of service.
3. Report vulnerabilities to program owners promptly.
4. Do not exploit vulnerabilities beyond proof-of-concept.

---

## 📄 License

MIT License – See LICENSE file for details.

---

**BBAT v3.0.0** — Built for authorized security research.

**GitHub:** https://github.com/Eliahhango/-BBAT-v3.0.0
