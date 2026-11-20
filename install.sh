#!/usr/bin/env bash
#
# Instalador de arpeggio.
#
# Crea un entorno aislado propio (no toca los paquetes del sistema),
# instala arpeggio y sus dependencias dentro, y deja el comando `arpeggio`
# en ~/.local/bin para que lo llames desde cualquier carpeta.
#
# Uso:  git clone ... && cd arpeggio && ./install.sh
#
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
venv="$data_home/arpeggio-venv"
bin_dir="$HOME/.local/bin"

echo "[*] Entorno aislado en: $venv"
python3 -m venv "$venv"
"$venv/bin/pip" install --quiet --upgrade pip

echo "[*] Instalando arpeggio y dependencias..."
"$venv/bin/pip" install --quiet "$here"

# limpiar la basura de compilacion que pip/setuptools dejan en el repo
rm -rf "$here/build" "$here"/*.egg-info

mkdir -p "$bin_dir"
ln -sf "$venv/bin/arpeggio" "$bin_dir/arpeggio"
echo "[+] Comando instalado: $bin_dir/arpeggio"

# Aviso de PATH
case ":$PATH:" in
    *":$bin_dir:"*)
        echo "[+] $bin_dir ya esta en tu PATH."
        echo "    Abre otra terminal y escribe: arpeggio" ;;
    *)
        echo "[!] $bin_dir NO esta en tu PATH. Anade esta linea a tu ~/.zshrc:"
        echo ""
        echo "        export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo ""
        echo "    Luego abre otra terminal y escribe: arpeggio" ;;
esac

# Comprobacion de nxc (no se instala aqui: es una herramienta aparte)
if command -v nxc >/dev/null 2>&1 || command -v netexec >/dev/null 2>&1; then
    echo "[+] netexec detectado."
else
    echo "[!] No encuentro nxc/netexec. arpeggio funciona igual, pero 'recon' y"
    echo "    'spray' lo necesitan. Instalalo con: pipx install netexec"
fi

echo "[*] Listo. Para desinstalar: ./uninstall.sh"
