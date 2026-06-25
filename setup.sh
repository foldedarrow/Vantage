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

# pipx-installed tools not always in apt
if command -v pipx >/dev/null 2>&1; then
  echo "[*] installing pipx tools (droopescan, arjun)"
  pipx install droopescan || true
  pipx install arjun || true
else
  echo "[!] pipx not found — skip droopescan/arjun, or: apt install pipx"
fi

# wpscan is a Ruby gem
if command -v gem >/dev/null 2>&1; then
  echo "[*] installing wpscan (gem)"
  gem install wpscan || true
fi

echo "[+] done. Now run: python run.py --check"
