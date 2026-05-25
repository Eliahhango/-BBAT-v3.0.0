#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# BBAT Bootstrap Installer
# Installs BBAT as a global `bbat` command — One-liner experience
# curl -sSL https://raw.githubusercontent.com/Eliahhango/-BBAT-v3.0.0/main/install.sh | bash
# ════════════════════════════════════════════════════════════════════

set -euo pipefail

REPO_URL="https://github.com/Eliahhango/-BBAT-v3.0.0.git"
INSTALL_DIR="${HOME}/.bbat"
VENV_DIR="${INSTALL_DIR}/venv"
SRC_DIR="${INSTALL_DIR}/src"
BBAT_BIN="/usr/local/bin/bbat"
PYTHON_BIN="python3"

# ─── ANSI Colors ───────────────────────────────────────────────────
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

# ─── Spinner ───────────────────────────────────────────────────────
spinner() {
  local pid=$1; local delay=0.08; local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  while ps -p $pid > /dev/null 2>&1; do
    local temp=${spinstr#?}
    printf "  %s%s \r" "$CYAN" "${spinstr:0:1}"
    spinstr=$temp${spinstr:0:1}
    sleep $delay
  done
  printf "       \r"
}

print_banner() {
  cat <<'EOF'
┏━┓┏━┓┏━━━┓┏━━━━┓
┃ ┗┛ ┃┃┏━┓┃┃┏┓┏┓┃
┃┏┓┏┓┃┃┃ ┃┃┗┛┃┃┗┛
┃┃┃┃┃┃┃┗━┛┃  ┃┃
┃┃┃┃┃┃┃┏━┓┃  ┃┃
┗┛┗┛┗┛┗┛ ┗┛  ┗┛
  Bug Bounty Automation Toolkit v3.2.0
EOF
}

print_step() { echo -e "${PURPLE}[●]${RESET} $1"; }
print_ok()   { echo -e "${GREEN}[✔]${RESET} $1"; }
print_warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
print_err()  { echo -e "${RED}[✘]${RESET} $1"; exit 1; }

# ════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════
print_banner
echo ""

# ── 1. Dependency Check ──
print_step "Checking dependencies..."
command -v git >/dev/null 2>&1 || print_err "git is required but not installed."
command -v $PYTHON_BIN >/dev/null 2>&1 || print_err "python3 is required but not installed."
command -v pip3 >/dev/null 2>&1 || print_err "pip3 is required but not installed."
print_ok "git, python3, and pip3 are present."

# ── 2. Create ~/.bbat skeleton ──
print_step "Preparing installation at ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"

# ── 3. Clone or pull repo ──
if [[ -d "${SRC_DIR}/.git" ]]; then
  print_step "Updating existing source..."
  (cd "$SRC_DIR" && git pull origin main) & spinner $!
else
  print_step "Cloning BBAT repository..."
  git clone --depth 1 "$REPO_URL" "$SRC_DIR" >/dev/null 2>&1 & spinner $!
fi
print_ok "Source code ready."

# ── 4. Build hidden virtual environment ──
print_step "Creating virtual environment at ${VENV_DIR}..."
if [[ ! -d "$VENV_DIR" ]]; then
  ($PYTHON_BIN -m venv "$VENV_DIR" >/dev/null 2>&1) & spinner $!
fi
print_ok "venv created."

# ── 5. Install python deps ──
print_step "Installing Python dependencies..."
"${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null 2>&1
("${VENV_DIR}/bin/pip" install -r "${SRC_DIR}/requirements.txt" >/dev/null 2>&1) & spinner $!
print_ok "Dependencies installed."

# ── 6. Install Playwright Chromium (optional) ──
print_step "Installing Playwright Chromium (optional)..."
("${VENV_DIR}/bin/python3" -m playwright install chromium >/dev/null 2>&1) & spinner $!
print_ok "Chromium browser ready."

# ── 7. Create global wrapper at /usr/local/bin/bbat ──
print_step "Creating global wrapper ${BBAT_BIN}..."

sudo tee "$BBAT_BIN" > /dev/null <<EOF
#!/usr/bin/env bash
# BBAT global launcher
set -e
VENV="\${HOME}/.bbat/venv"
SRC="\${HOME}/.bbat/src"

# Ensure python path resolves modules relative to SRC
export PYTHONPATH="\${SRC}/modules:\${PYTHONPATH:-}"

# Default: launch TUI
exec "\${VENV}/bin/python3" "\${SRC}/tui.py" "\$@"
EOF

sudo chmod +x "$BBAT_BIN"
print_ok "Wrapper installed."

# ── 8. Permission fix for source files ──
chmod -R 755 "$INSTALL_DIR"

# ── 9. Success banner ──
cat <<EOF

${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}
${GREEN}  BBAT v3.2.0 installed successfully!${RESET}
${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}

${CYAN}Launch:${RESET}
    bbat

${CYAN}Or for CLI mode:${RESET}
    bbat full example.com

${CYAN}Or module-specific:${RESET}
    bbat recon example.com

${PURPLE}Directory layout:${RESET}
    ~/.bbat/venv     → Python environment
    ~/.bbat/src      → BBAT source code
    /usr/local/bin/bbat → Global launcher

${GREEN}Type 'bbat' to start the Dracula TUI. Enjoy hunting!${RESET}

EOF
