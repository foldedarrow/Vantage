#!/usr/bin/env bash
# ctfauto toolchain bootstrap for Kali/Debian. Installs the external CLI tools
# ctfauto orchestrates. Re-run any time; apt is idempotent.
#
#   sudo ./setup.sh
#
# After this, run `python run.py --check` (or `ctfauto --check`) to see what's
# present and what's still missing.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[!] Run as root (sudo ./setup.sh) — apt needs it." >&2
  exit 1
fi

APT_PKGS=(
  nmap gobuster feroxbuster nikto hydra exploitdb
  metasploit-framework enum4linux smbclient whatweb ffuf
  onesixtyone snmp snmp-check sslscan sqlmap
  default-mysql-client nfs-common seclists wordlists
)

echo "[*] apt update"
apt-get update -y

echo "[*] installing CLI toolchain"
apt-get install -y "${APT_PKGS[@]}" || {
  echo "[!] some apt packages failed (name drift across distros is normal)."
  echo "    Re-run 'ctfauto --check' to see what's still missing."
}

# pipx-installed tools not always in apt
if command -v pipx >/dev/null 2>&1; then
  echo "[*] installing pipx tools (droopescan, git-dumper, arjun)"
  pipx install droopescan || true
  pipx install git-dumper || true
  pipx install arjun || true
else
  echo "[!] pipx not found — skip droopescan/git-dumper/arjun, or: apt install pipx"
fi

# wpscan is a Ruby gem
if command -v gem >/dev/null 2>&1; then
  echo "[*] installing wpscan (gem)"
  gem install wpscan || true
fi

# Optional Python dep for msfrpc post-exploitation
echo "[*] installing pymetasploit3 (for --post-exploit over msfrpc)"
pip install --break-system-packages pymetasploit3 || pip install pymetasploit3 || true

# PEAS scripts for privesc enumeration
PEAS_DIR=/usr/share/peass
echo "[*] fetching linpeas/winPEAS into ${PEAS_DIR} (best-effort)"
mkdir -p "${PEAS_DIR}"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL -o "${PEAS_DIR}/linpeas.sh" \
    https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh || \
    echo "    (couldn't fetch linpeas — download it manually into ${PEAS_DIR})"
fi

echo "[+] done. Now run: python run.py --check"
