# 🐛 BBAT - Bug Bounty Automation Toolkit v3.2.0

**One-line installer:**

```bash
curl -sSL https://raw.githubusercontent.com/Eliahhango/-BBAT-v3.0.0/main/install.sh | bash
```

**Then simply type:**

```bash
bbat
```

That's it. The Dracula-themed TUI launches instantly.

---

## 🚀 Quick Start

```bash
# 1. Install (one command)
curl -sSL https://raw.githubusercontent.com/Eliahhango/-BBAT-v3.0.0/main/install.sh | bash

# 2. Launch TUI
bbat

# 3. Or use CLI mode for automation
bbat full example.com
bbat recon example.com
bbat scan https://example.com
```

**Repository:** https://github.com/Eliahhango/-BBAT-v3.0.0

---

## 🎨 TUI Interface

| Key | Action |
|-----|--------|
| `Ctrl+S` | Save report to JSON |
| `Ctrl+K` | Stop running scan |
| `Ctrl+Q` | Quit BBAT |

The TUI features:
- Dracula color theme
- Module selector with checkboxes
- Live log with color-coded output
- Dynamic findings table
- Global progress bar
- Side-panel module status tracker

---

## 🎮 CLI Reference

```bash
bbat recon        example.com
bbat scan         https://example.com
bbat fuzz         https://example.com
bbat crawl        https://example.com
bbat takeover     example.com
bbat fingerprint  https://example.com
bbat ctlog        example.com
bbat wayback      example.com
bbat s3           example.com
bbat gitscan      https://example.com
bbat nuclei       https://example.com
bbat waf          https://example.com
bbat api_fuzz     https://api.example.com
bbat full         example.com
bbat dashboard    # Flask web dashboard
```

---

## 📦 What Gets Installed

```
~/.bbat/venv     → Python virtual environment (hidden, isolated)
~/.bbat/src      → BBAT source code synced from GitHub
/usr/local/bin/bbat → Global launcher (requires sudo)
```

No manual `pip install`, no `cd` into folders, no local file management.

---

## 🚢 Docker (optional)

```bash
docker build -t bbat .
docker run --rm -p 5000:5000 bbat dashboard
```

---

## 🔒 Responsible Disclosure

This tool is intended solely for authorized bug bounty programs and penetration testing engagements with explicit written permission. Unauthorized access is illegal.

---

## 📄 License

MIT License

---

**BBAT v3.2.0** — Built for authorized security research.

**GitHub:** https://github.com/Eliahhango/-BBAT-v3.0.0
