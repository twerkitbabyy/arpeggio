#!/usr/bin/env bash
#
# Desinstala arpeggio: quita el comando y el entorno aislado.
# NO borra tus engagements guardados (eso lo decides tu).
#
set -euo pipefail

data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
venv="$data_home/arpeggio-venv"
bin_dir="$HOME/.local/bin"

rm -f "$bin_dir/arpeggio"
rm -rf "$venv"
echo "[+] arpeggio desinstalado (comando y entorno)."
echo "[*] Tus engagements siguen en: $data_home/arpeggio"
echo "    Para borrarlos tambien:  rm -rf \"$data_home/arpeggio\""
