#!/usr/bin/env bash
# vantage toolchain bootstrap for Kali/Debian. Installs the external CLI tools
# vantage orchestrates. Re-run any time; apt is idempotent.
#
#   sudo ./setup.sh
#
# After this, run `python run.py --check` (or `vantage --check`) to see what's
# present and what's still missing.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[!] Run as root (sudo ./setup.sh) — apt needs it." >&2
  exit 1
fi

APT_PKGS=(
  nmap gobuster feroxbuster nikto exploitdb
  enum4linux smbclient whatweb ffuf
  onesixtyone snmp snmp-check sslscan
  nfs-common seclists wordlists
)

echo "[*] apt update"
apt-get update -y

echo "[*] installing CLI toolchain"
apt-get install -y "${APT_PKGS[@]}" || {
  echo "[!] some apt packages failed (name drift across distros is normal)."
  echo "    Re-run 'vantage --check' to see what's still missing."
}

# pipx-installed tools not always in apt.
#
# IMPORTANT: install these GLOBALLY (--global → /usr/local/bin), not per-user.
# vantage is normally run under sudo (nmap wants root), and sudo's secure_path
# only includes /usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin. A plain per-user
# `pipx install` lands in ~/.local/bin, which sudo never sees — so the tools
# would show as missing in `vantage --check` even though they're installed.
PIPX_PKGS=(droopescan arjun bloodhound certipy-ad git-dumper)

if ! command -v pipx >/dev/null 2>&1; then
  echo "[*] pipx not found — installing via apt"
  apt-get install -y pipx || true
fi

if command -v pipx >/dev/null 2>&1; then
  echo "[*] ensuring global pipx path"
  pipx ensurepath --global >/dev/null 2>&1 || true
  echo "[*] installing pipx tools globally (${PIPX_PKGS[*]})"
  for pkg in "${PIPX_PKGS[@]}"; do
    pipx install --global "$pkg" || echo "[!] pipx install --global $pkg failed (continuing)"
  done
else
  echo "[!] pipx still unavailable — skipping ${PIPX_PKGS[*]}"
fi

# kerbrute: no apt/pipx package. Drop the release binary in /usr/local/bin so it
# lands on sudo's secure_path (go install would put it in ~/go/bin, invisible to sudo).
echo "[*] installing kerbrute (release binary -> /usr/local/bin)"
if curl -fsSL -o /usr/local/bin/kerbrute \
     https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64; then
  chmod +x /usr/local/bin/kerbrute
else
  echo "[!] kerbrute download failed — grab a release binary manually, or: go install github.com/ropnop/kerbrute@latest"
fi

# wpscan is a Ruby gem
if command -v gem >/dev/null 2>&1; then
  echo "[*] installing wpscan (gem)"
  gem install wpscan || true
fi

echo "[+] done. Now run: sudo python run.py --check"
