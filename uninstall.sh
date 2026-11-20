#!/usr/bin/env bash
#
# Uninstalls arpeggio: removes the command and the isolated environment.
# It does NOT delete your saved engagements (that is your call).
#
set -euo pipefail

data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
venv="$data_home/arpeggio-venv"
bin_dir="$HOME/.local/bin"

rm -f "$bin_dir/arpeggio"
rm -rf "$venv"
echo "[+] arpeggio uninstalled (command and environment)."
echo "[*] Your engagements are still in: $data_home/arpeggio"
echo "    To remove them too:  rm -rf \"$data_home/arpeggio\""
