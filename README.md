# 🐛 BBAT - Bug Bounty Automation Toolkit v3.3.0

**One-line installer:**

```bash
curl -sSL https://raw.githubusercontent.com/Eliahhango/-BBAT-v3.0.0/main/install.sh | bash
```

**Then simply type:**

```bash
bbat
```

The operator-grade TUI launches instantly. True-black background, neon purple accent, minimal chrome.

---

## 🎮 TUI Interface v3.3.0

```
 ▄▄▄▄    ▄▄▄      ▄▄▄      ▄███▄   █▄▄▄▄
 ...
 Welcome, operator.
 Syntax: target.com,module1,module2  (or 'all')
 Modules: recon, ctlog, crawler, fuzzer, scanner, takeover, s3, gitscan, fingerprint, waf, api_fuzz, screenshot

 example.com,recon,waf,scanner  —  press ENTER to execute
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [live log — 90% of screen]

 ┏ ALERT: CRITICAL
 ┃ TYPE: open_redirect
 ┃ DESC: Open redirect found at ...
 ┃ URL:  https://example.com/redirect?url=...
 ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 ctrl+s save | ctrl+c abort | ctrl+q quit
```

| Key | Action |
|-----|--------|
| `Enter` | Execute command in the input bar |
| `Ctrl+S` | Save report to JSON |
| `Ctrl+C` | Abort running scan |
| `Ctrl+Q` | Quit BBAT |

---

## 🛠 CLI Reference

All commands work via `bbat <command> <target>`:

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
~/.bbat/venv     → Hidden Python environment (isolated)
~/.bbat/src      → BBAT source code synced from GitHub
/usr/local/bin/bbat → Global launcher (sudo required)
```

No manual pip install, no cd into folders, no local file management. Pure seamless operator experience.

---

## 🔒 Responsible Disclosure

This tool is intended solely for authorized bug bounty programs and penetration testing engagements with explicit written permission. Unauthorized access is illegal.

---

## 📄 License

MIT License

---

**BBAT v3.3.0** — Operator-grade security research.

**GitHub:** https://github.com/Eliahhango/-BBAT-v3.0.0
