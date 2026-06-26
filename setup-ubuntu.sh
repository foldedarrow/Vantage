#!/usr/bin/env bash
# vantage toolchain bootstrap for **Ubuntu** (tested on 24.04 LTS).
#
# Unlike setup.sh (Kali/apt), about half of vantage's toolchain isn't in Ubuntu's
# repos, so this installs across several channels — apt, Go, pipx, gem, and git.
# Every binary is forced into /usr/local/bin so it's on **root's** PATH too: you
# run scans with `sudo python3 run.py`, and sudo's PATH won't include ~/.local/bin
# or ~/go/bin. Landing everything in /usr/local/bin avoids that whole class of
# "installed but not found under sudo" confusion.
#
#   sudo ./setup-ubuntu.sh                 # full install
#   sudo SKIP_SECLISTS=1 ./setup-ubuntu.sh # skip the large SecLists clone
#
# Re-run any time — every step is idempotent. Afterwards:
#   sudo python3 run.py --check
set -uo pipefail   # NOT -e: one tool failing must not abort the whole bootstrap

if [[ $EUID -ne 0 ]]; then
  echo "[!] Run as root: sudo ./setup-ubuntu.sh" >&2
  exit 1
fi

# Binaries from Go/cargo/pipx all get directed here so root (sudo) finds them.
BIN=/usr/local/bin
export DEBIAN_FRONTEND=noninteractive
OK=(); FAIL=()
note_ok()   { OK+=("$1"); }
note_fail() { FAIL+=("$1"); echo "[!] FAILED: $1" >&2; }

# ---------------------------------------------------------------------------
# 1. apt — everything Ubuntu *does* ship (universe). Installed one-by-one so a
#    single unavailable package doesn't abort the batch.
# ---------------------------------------------------------------------------
echo "[*] apt update"
apt-get update -y || true

APT_PKGS=(
  # core recon / enum (all in Ubuntu main/universe)
  nmap nikto smbclient samba-common-bin curl wget
  snmp onesixtyone sslscan ldap-utils nfs-common whatweb
  # exploit-identification lead helpers (vantage only *detects* these; never fires)
  sqlmap hydra default-mysql-client
  # build/install prerequisites for the non-apt channels below
  # (enum4linux + awscli aren't in 24.04 repos — handled via git/pipx below)
  # rustc/cargo: NetExec pulls a dependency that builds from Rust source.
  git golang-go ruby ruby-dev pipx python3-venv build-essential rustc cargo
)
echo "[*] installing apt packages"
for pkg in "${APT_PKGS[@]}"; do
  if apt-get install -y "$pkg" >/dev/null 2>&1; then
    note_ok "apt:$pkg"
  else
    note_fail "apt:$pkg"
  fi
done

# ---------------------------------------------------------------------------
# 2. Go tools → installed straight into /usr/local/bin via GOBIN.
# ---------------------------------------------------------------------------
if command -v go >/dev/null 2>&1; then
  echo "[*] installing Go tools (gobuster, ffuf, kerbrute)"
  export GOBIN="$BIN" GOPATH="${GOPATH:-/root/go}" GOFLAGS=-mod=mod
  go_install() { # name  module@version
    if GOBIN="$BIN" go install "$2" >/dev/null 2>&1; then note_ok "go:$1"; else note_fail "go:$1"; fi
  }
  go_install gobuster  github.com/OJ/gobuster/v3@latest
  go_install ffuf      github.com/ffuf/ffuf/v2@latest
  go_install kerbrute  github.com/ropnop/kerbrute@latest
else
  note_fail "go (golang-go not installed — gobuster/ffuf/kerbrute skipped)"
fi

# ---------------------------------------------------------------------------
# 3. feroxbuster → official prebuilt binary (avoids a full Rust toolchain).
# ---------------------------------------------------------------------------
echo "[*] installing feroxbuster (prebuilt binary)"
if curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
     | bash -s "$BIN" >/dev/null 2>&1 && [[ -x "$BIN/feroxbuster" ]]; then
  note_ok "feroxbuster"
else
  note_fail "feroxbuster (retry: cargo install feroxbuster --root /usr/local)"
fi

# ---------------------------------------------------------------------------
# 4. pipx tools → venvs under /opt/pipx, binaries symlinked into /usr/local/bin.
#    PIPX_BIN_DIR is the key bit: keeps them on root's PATH for `sudo run.py`.
# ---------------------------------------------------------------------------
if command -v pipx >/dev/null 2>&1; then
  echo "[*] installing pipx tools"
  export PIPX_HOME=/opt/pipx PIPX_BIN_DIR="$BIN"
  pipx_install() { # label  pip-spec
    if pipx install --force "$2" >/dev/null 2>&1; then note_ok "pipx:$1"; else note_fail "pipx:$1"; fi
  }
  pipx_install droopescan     droopescan
  pipx_install arjun          arjun
  pipx_install git-dumper     git-dumper
  pipx_install impacket       impacket          # → impacket-GetNPUsers / GetUserSPNs / lookupsid
  pipx_install netexec        "git+https://github.com/Pennyw0rth/NetExec"   # → nxc / netexec (not on PyPI; needs rustc)
  pipx_install enum4linux-ng  "git+https://github.com/cddmp/enum4linux-ng"  # → enum4linux-ng (not on PyPI)
  pipx_install bloodhound     bloodhound        # → bloodhound-python
  pipx_install certipy        certipy-ad        # → certipy
  pipx_install ldapdomaindump ldapdomaindump
  pipx_install s3scanner      s3scanner
  pipx_install cloud_enum     "git+https://github.com/initstring/cloud_enum"
  pipx_install awscli         awscli            # → aws (not in 24.04 apt repos)

  # pip's impacket exposes scripts as `GetNPUsers.py` etc.; vantage looks for the
  # Kali-style `impacket-*` names — symlink the ones it checks for.
  for s in GetNPUsers GetUserSPNs lookupsid; do
    if [[ -e "$BIN/$s.py" ]]; then ln -sf "$BIN/$s.py" "$BIN/impacket-$s"; note_ok "impacket-$s"; fi
  done
else
  note_fail "pipx (not installed — droopescan/arjun/impacket/netexec/etc. skipped)"
fi

# ---------------------------------------------------------------------------
# 5. wpscan → Ruby gem (binstub lands in /usr/local/bin as root).
# ---------------------------------------------------------------------------
if command -v gem >/dev/null 2>&1; then
  echo "[*] installing wpscan (gem)"
  if gem install wpscan >/dev/null 2>&1; then note_ok "gem:wpscan"; else note_fail "gem:wpscan"; fi
else
  note_fail "gem (ruby not installed — wpscan skipped)"
fi

# ---------------------------------------------------------------------------
# 6. searchsploit (Exploit-DB) → git clone + symlink (not in Ubuntu repos).
# ---------------------------------------------------------------------------
echo "[*] installing searchsploit (exploitdb)"
if [[ -d /opt/exploitdb/.git ]]; then
  git -C /opt/exploitdb pull --quiet || true
else
  git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb >/dev/null 2>&1 || true
fi
if [[ -x /opt/exploitdb/searchsploit ]]; then
  ln -sf /opt/exploitdb/searchsploit "$BIN/searchsploit"
  note_ok "searchsploit"
else
  note_fail "searchsploit"
fi

# ---------------------------------------------------------------------------
# 6b. enum4linux → Perl script, git clone + symlink (dropped from 24.04 repos).
#     (enum4linux-ng is installed via pipx above; vantage detects either.)
# ---------------------------------------------------------------------------
echo "[*] installing enum4linux (git)"
if [[ -d /opt/enum4linux/.git ]]; then
  git -C /opt/enum4linux pull --quiet || true
else
  git clone --depth 1 https://github.com/CiscoCXSecurity/enum4linux.git /opt/enum4linux >/dev/null 2>&1 || true
fi
if [[ -f /opt/enum4linux/enum4linux.pl ]]; then
  chmod +x /opt/enum4linux/enum4linux.pl
  ln -sf /opt/enum4linux/enum4linux.pl "$BIN/enum4linux"
  note_ok "enum4linux"
else
  note_fail "enum4linux"
fi

# ---------------------------------------------------------------------------
# 7. Wordlists — SecLists + rockyou, at the paths vantage's resolver checks.
# ---------------------------------------------------------------------------
if [[ "${SKIP_SECLISTS:-0}" == "1" ]]; then
  echo "[*] SKIP_SECLISTS=1 — skipping SecLists/rockyou (point --seclists-dir yourself)"
else
  echo "[*] installing SecLists → /usr/share/seclists (large clone, be patient)"
  if [[ -d /usr/share/seclists/.git ]]; then
    git -C /usr/share/seclists pull --quiet || true
  else
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists >/dev/null 2>&1 || true
  fi
  [[ -d /usr/share/seclists ]] && note_ok "seclists" || note_fail "seclists"

  # rockyou: vantage looks for /usr/share/wordlists/rockyou.txt — source it from SecLists.
  mkdir -p /usr/share/wordlists
  ROCKYOU_GZ=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz
  if [[ ! -f /usr/share/wordlists/rockyou.txt && -f "$ROCKYOU_GZ" ]]; then
    tar -xzf "$ROCKYOU_GZ" -C /usr/share/wordlists 2>/dev/null || true
  fi
  [[ -f /usr/share/wordlists/rockyou.txt ]] && note_ok "rockyou" || note_fail "rockyou (optional)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "==================================================================="
echo " Installed OK (${#OK[@]}): ${OK[*]:-none}"
echo
echo " Failed / skipped (${#FAIL[@]}): ${FAIL[*]:-none}"
echo "==================================================================="
echo
echo "Notes:"
echo "  * snmp-check is Kali-only and has no clean Ubuntu source — vantage just"
echo "    skips it; onesixtyone + snmpwalk cover SNMP enumeration."
echo "  * Anything above that failed: re-run, or install it by hand, then"
echo "  * Verify the full matrix:  sudo python3 run.py --check"
