# arpeggio

Consola interactiva para recon y gestion de credenciales en Active
Directory, construida sobre [netexec](https://github.com/Pennant/NetExec) (nxc).

La dejas abierta durante una maquina o un prolab. Lanzas `recon` contra
un host y toda la enumeracion sin credenciales (sesion nula + guest, SMB
+ LDAP) se guarda dentro del programa. Cuando encuentras una credencial
la metes con `add` y con `spray` la pruebas contra todos los hosts de
golpe, marcando donde entra y donde eres admin. Todo se autoguarda en un
JSON por engagement, asi que puedes cerrarlo y seguir manana.

Nace de una pereza concreta: no tener que escribir siempre a mano los 6+
comandos de recon (`--shares`, `--users`, `--rid-brute`, `--pass-pol`...)
con sesion nula **y** con guest cada vez que pisas una maquina.

## Instalacion

```bash
git clone https://github.com/twerkitbabyy/arpeggio
cd arpeggio
./install.sh
```

El `install.sh` crea un entorno aislado propio (no toca los paquetes del
sistema, Arch lo agradece), instala arpeggio dentro y deja el comando
`arpeggio` en `~/.local/bin`. Abre otra terminal y ya lo tienes disponible
desde cualquier carpeta. Si `~/.local/bin` no esta en tu PATH, el script
te lo avisa y te da la linea que anadir al `~/.zshrc`.

Para desinstalar: `./uninstall.sh` (no borra tus engagements guardados).

Necesita `nxc`/`netexec` aparte en el PATH para `recon` y `spray`
(`pipx install netexec`). Sin ellos el resto de la consola funciona
igual, y tienes `--mock`.

Tambien puedes correrlo sin instalar, desde el repo:

```bash
python3 -m pip install rich prompt_toolkit
python3 -m arpeggio
```

## Persistencia: por defecto no guarda nada

arpeggio arranca **en memoria**. Mientras no digas lo contrario, no escribe
nada en el disco: haces una maquina simple, cierras, y no queda rastro.

Cuando quieras conservar una sesion (p. ej. un prolab como Dante),
dentro de la consola:

```
arpeggio> keep dante        # a partir de aqui se guarda, con el nombre 'dante'
```

Desde ese momento se autoguarda. Al dia siguiente, aunque reinicies:

```
arpeggio> engagements       # lista lo guardado -> ahi sale 'dante'
arpeggio> load dante        # lo carga tal cual lo dejaste
arpeggio> forget dante      # cuando ya no lo quieras, lo borra (pide confirmacion)
```

Lo guardado vive **todo en una carpeta**: `~/.local/share/arpeggio/`
(o `$XDG_DATA_HOME/arpeggio`). Nunca se escribe en la carpeta desde la que
lanzas. Dentro, por cada engagement conservado:

| fichero | que es |
|---|---|
| `<nombre>.json` | el engagement (hosts, usuarios, creds, shares, salida cruda) |
| `<nombre>.asrep` | hashes AS-REP del recon, listos para crackear |
| `history` | historial de comandos de la consola (uno solo, como el del shell) |

El comando `where` te dice en todo momento si la sesion se esta guardando
y donde. Para empezar de cero: `rm -rf ~/.local/share/arpeggio/`.

## Uso

```bash
arpeggio              # sesion en memoria (no se guarda hasta que hagas 'keep')
arpeggio dante        # abre/crea el engagement 'dante' ya conservado
arpeggio -f /ruta/x.json   # un JSON en una ruta concreta, si lo necesitas
arpeggio --mock       # sin nxc, con salida de ejemplo (para cacharrear)
```

Dentro, `help` lo lista todo. Flujo tipico:

```
arpeggio> target 10.10.11.45 DC01    # fija el host activo
arpeggio> recon                      # ronda completa null+guest, SMB+LDAP
arpeggio> users                      # lo que ha sacado
arpeggio> shares
arpeggio> passpol                    # OJO al umbral de bloqueo antes de spray
arpeggio> add cred jdoe 'Summer2026!'
arpeggio> add hash administrator aad3b4...:31d6cfe0d16ae931b73c59d7e0c089c0
arpeggio> spray all                  # prueba todas las creds x todos los hosts (smb+winrm)
arpeggio> creds                      # donde valen y donde eres admin (Pwn3d)
```

### Que hace `recon`

Sobre el host:

1. Prueba sesion **nula** y **guest** por SMB, y se queda con la(s) que conecte(n).
2. Bajo esa auth lanza: `--pass-pol`, `--shares`, `--users`, `--groups`, `--loggedon-users`, `--sessions`.
3. Si `--users` viene vacio, tira de `--rid-brute` automaticamente.
4. Prueba **LDAP con bind anonimo** (`--users` y `--asreproast`), que a veces suelta usuarios con el SMB cerrado.

Todo cae en el almacen y la salida cruda de cada comando queda guardada
(comando `log` para la lista, `raw <id>` para verla entera). Si netexec
cambia algun formato y el parseo falla, nunca pierdes la info: el texto
crudo sigue ahi.

## Estructura

```
arpeggio/
  install.sh / uninstall.sh   instalador aislado + comando en ~/.local/bin
  pyproject.toml              paquete y dependencias (entry point 'arpeggio')
  arpeggio/
    cli.py        la consola interactiva y las tablas
    core.py       modelo de datos (Host, User, Cred, Share, Run) y guardado JSON
    nxcwrap.py    runner de nxc, parsers y la orquestacion de la ronda de recon
    mockrunner.py runner falso con salida de ejemplo para --mock y los tests
  tests/
    test_smoke.py prueba parsers, recon, spray y roundtrip JSON sin nxc
```

La logica de nxc esta separada de la interfaz a proposito: si algun dia
la quieres con paneles de verdad (Textual), solo cambias `cli.py`.

## Avisos

- Herramienta para labs y engagements autorizados.
- `spray` prueba **un** secreto conocido por usuario, no un diccionario,
  asi que el riesgo de bloqueo es bajo; aun asi te recuerda el umbral de
  bloqueo del dominio si lo ha visto en `--pass-pol`.
