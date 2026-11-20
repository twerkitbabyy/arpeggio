#!/usr/bin/env bash
#
# arpeggio installer.
#
# Creates its own isolated environment (does not touch system packages),
# installs arpeggio and its dependencies inside it, and drops the
# `arpeggio` command in ~/.local/bin so you can call it from any folder.
#
# Usage:  git clone ... && cd arpeggio && ./install.sh
#
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
venv="$data_home/arpeggio-venv"
bin_dir="$HOME/.local/bin"

echo "[*] Isolated environment at: $venv"
python3 -m venv "$venv"
"$venv/bin/pip" install --quiet --upgrade pip

echo "[*] Installing arpeggio and dependencies (editable)..."
# editable install: the command points straight at these source files, so a
# later 'git pull' updates the running tool with no reinstall needed.
"$venv/bin/pip" install --quiet -e "$here"

# drop the build scratch dir (the .egg-info is needed by the editable install)
rm -rf "$here/build"

mkdir -p "$bin_dir"
ln -sf "$venv/bin/arpeggio" "$bin_dir/arpeggio"
echo "[+] Command installed: $bin_dir/arpeggio"

# PATH check
case ":$PATH:" in
    *":$bin_dir:"*)
        echo "[+] $bin_dir is already in your PATH."
        echo "    Open a new terminal and run: arpeggio" ;;
    *)
        echo "[!] $bin_dir is NOT in your PATH. Add this line to your ~/.zshrc:"
        echo ""
        echo "        export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo ""
        echo "    Then open a new terminal and run: arpeggio" ;;
esac

# nxc check (not installed here: it is a separate tool)
if command -v nxc >/dev/null 2>&1 || command -v netexec >/dev/null 2>&1; then
    echo "[+] netexec detected."
else
    echo "[!] nxc/netexec not found. arpeggio still works, but 'recon' and"
    echo "    'spray' need it. Install it with: pipx install netexec"
fi

echo "[*] Done. To uninstall: ./uninstall.sh"
