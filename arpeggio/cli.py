#!/usr/bin/env python3
"""
arpeggio - consola interactiva para recon y credenciales de Active Directory.

La idea: la dejas abierta durante una maquina o un prolab, vas lanzando
`recon`, y todo lo que descubre (usuarios, shares, politica de
contrasenas, dominio) se queda guardado dentro. Cuando encuentras una
credencial la metes con `add` y con `spray` la pruebas contra todos los
hosts de golpe, marcando donde entra y donde eres admin.

Uso:
    python3 arpeggio.py                 # engagement ./arpeggio.json
    python3 arpeggio.py -f cliente.json # otro fichero
    python3 arpeggio.py --mock          # sin nxc, con salida de ejemplo (demo/tests)

Dentro, escribe `help`.
"""

from __future__ import annotations

import argparse
import shlex
from pathlib import Path

from .core import Engagement, data_dir, list_engagements
from .nxcwrap import Runner, recon, auth_ok, parse_pwned

try:
    from rich.console import Console as RichConsole
    from rich.table import Table
    from rich import box
    _RICH = True
except ImportError:                      # degradar con dignidad si falta rich
    _RICH = False

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import FileHistory
    _PTK = True
except ImportError:
    _PTK = False


COMMANDS = [
    "help", "status", "where", "keep", "engagements", "load", "forget",
    "target", "recon", "hosts", "users", "creds",
    "shares", "groups", "passpol", "add", "spray", "log", "raw",
    "save", "clear", "exit", "quit",
]

HELP = """\
Comandos:
  status                      resumen rapido del engagement
  where                       rutas / si esta sesion se guarda o no
  keep [nombre]               conservar: a partir de aqui se guarda en disco
  engagements                 lista los engagements guardados
  load <nombre>               carga un engagement guardado
  forget <nombre>             borra un engagement guardado
  target <ip> [nombre]        fija el host activo (y lo da de alta)
  recon [ip]                  ronda completa null+guest, SMB+LDAP (host activo si no das ip)
  hosts                       hosts descubiertos
  users                       usuarios descubiertos
  creds                       credenciales y donde funcionan
  shares [ip]                 shares (todos, o de un host)
  groups                      grupos del dominio (resalta los jugosos)
  passpol                     politica de contrasenas / umbral de bloqueo
  add host <ip> [nombre]      alta manual de host
  add user <usuario>          alta manual de usuario
  add cred <usuario> <pass>   alta de credencial (contrasena)
  add hash <usuario> <hash>   alta de credencial (hash NTLM)
  spray [smb|winrm|all]       prueba TODAS las creds contra TODOS los hosts
  log                         comandos nxc lanzados
  raw <id>                    salida cruda de un comando (id de `log`)
  save                        fuerza guardado (de todas formas se autoguarda)
  clear                       limpia la pantalla
  exit / quit                 salir
"""

JUICY_GROUPS = ("domain admins", "enterprise admins", "administrators",
                "schema admins", "backup operators", "account operators",
                "dnsadmins", "remote desktop users")


class Console:
    """Estado + logica de los comandos. Separado del REPL para poder testear."""

    def __init__(self, engagement: Engagement, runner: Runner):
        self.e = engagement
        self.runner = runner
        self.active_host: str | None = None
        self.out = RichConsole() if _RICH else None
        # rutas auxiliares (las rellena main); sirven para 'where' y recon
        self.hist_path: Path | None = None
        self.asrep_path: Path | None = None

    # ---- utilidades de impresion ----

    def p(self, *a, **kw):
        if self.out:
            self.out.print(*a, **kw)
        else:
            print(*[str(x) for x in a])

    def warn(self, msg):
        self.p(f"[yellow]! {msg}[/yellow]" if _RICH else f"! {msg}")

    def err(self, msg):
        self.p(f"[red]x {msg}[/red]" if _RICH else f"x {msg}")

    def ok(self, msg):
        self.p(f"[green]{msg}[/green]" if _RICH else msg)

    def _table(self, title, cols):
        if _RICH:
            t = Table(title=title, box=box.SIMPLE_HEAVY, title_style="bold")
            for c in cols:
                t.add_column(c)
            return t
        self.p(f"\n== {title} ==")
        self.p(" | ".join(cols))
        return None

    def _emit(self, table, rows):
        if _RICH and table is not None:
            for r in rows:
                table.add_row(*[str(x) for x in r])
            self.p(table)
        else:
            for r in rows:
                self.p(" | ".join(str(x) for x in r))

    # ---- dispatch ----

    def dispatch(self, line: str) -> bool:
        """Ejecuta una linea. Devuelve False para salir del REPL."""
        line = line.strip()
        if not line:
            return True
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]

        handler = {
            "help": self.c_help, "?": self.c_help,
            "status": self.c_status,
            "where": self.c_where,
            "keep": self.c_keep,
            "engagements": self.c_engagements,
            "load": self.c_load,
            "forget": self.c_forget,
            "target": self.c_target,
            "recon": self.c_recon,
            "hosts": self.c_hosts,
            "users": self.c_users,
            "creds": self.c_creds,
            "shares": self.c_shares,
            "groups": self.c_groups,
            "passpol": self.c_passpol,
            "add": self.c_add,
            "spray": self.c_spray,
            "log": self.c_log,
            "raw": self.c_raw,
            "save": lambda a: (self.e.save(), self.ok("guardado")),
            "clear": lambda a: (self.out.clear() if _RICH else None),
        }.get(cmd)

        if cmd in ("exit", "quit"):
            return False
        if handler is None:
            self.err(f"comando desconocido: {cmd}  (escribe 'help')")
            return True
        handler(args)
        return True

    # ---- comandos ----

    def c_help(self, _args):
        self.p(HELP)

    def c_status(self, _args):
        self.p(f"[bold]{self.e.name}[/bold]  dominio: {self.e.domain or '?'}  "
               f"activo: {self.active_host or '-'}" if _RICH else
               f"{self.e.name}  dominio: {self.e.domain or '?'}  activo: {self.active_host or '-'}")
        self.p(f"hosts: {len(self.e.hosts)}   usuarios: {len(self.e.users)}   "
               f"creds: {len(self.e.creds)}   shares: {len(self.e.shares)}   "
               f"comandos: {len(self.e.runs)}")
        self.p("guardado: SI" if self.e.keep else
               "guardado: NO (solo memoria; 'keep <nombre>' para conservar)")
        if self.e.lockout_threshold:
            self.warn(f"umbral de bloqueo: {self.e.lockout_threshold}")

    def c_where(self, _args):
        if not self.e.keep:
            self.warn("esta sesion NO se esta guardando (solo en memoria)")
            self.p("Usa 'keep <nombre>' para conservarla a partir de ahora.")
            self.p(f"\nSi la guardas, iria a: {data_dir()}")
            return
        self.p("Esta sesion se guarda. Todo vive en un solo sitio:")
        self.p(f"  carpeta de datos : {data_dir()}")
        self.p(f"  engagement (JSON): {self.e._path}")
        if self.hist_path:
            self.p(f"  historial        : {self.hist_path}")
        if self.asrep_path:
            self.p(f"  hashes AS-REP    : {self.asrep_path}")
        self.p("\nNada se escribe en la carpeta desde la que lanzas el programa.")

    def c_keep(self, args):
        name = args[0] if args else self.e.name
        dd = data_dir()
        path = dd / f"{name}.json"
        if path.exists() and path != self.e._path:
            self.err(f"ya existe un engagement '{name}'. Usa 'load {name}' o elige otro nombre")
            return
        self.e.name = name
        self.e.keep = True
        self.e._path = path
        self.e._autosave = True
        self.asrep_path = dd / f"{name}.asrep"
        self.e.save()
        self.ok(f"conservado. A partir de ahora se guarda en {path}")

    def c_engagements(self, _args):
        items = list_engagements()
        if not items:
            self.warn("no hay engagements guardados todavia")
            return
        t = self._table("Engagements guardados",
                        ["Nombre", "Hosts", "Users", "Creds", "Actualizado"])
        rows = [[it["name"], it["hosts"], it["users"], it["creds"], it["updated"]]
                for it in items]
        self._emit(t, rows)
        self.p("[dim]usa 'load <nombre>' para cargar uno[/dim]" if _RICH
               else "usa 'load <nombre>' para cargar uno")

    def c_load(self, args):
        if not args:
            self.err("uso: load <nombre>  (mira 'engagements')")
            return
        dd = data_dir()
        path = dd / f"{args[0]}.json"
        if not path.exists():
            self.err(f"no existe el engagement '{args[0]}'")
            return
        self.e.save()                    # guarda el actual si estaba conservado
        self.e = Engagement.load(path)
        self.asrep_path = dd / f"{path.stem}.asrep"
        self.active_host = None
        self.ok(f"cargado '{self.e.name}'")
        self.c_status([])

    def c_forget(self, args):
        if not args:
            self.err("uso: forget <nombre>")
            return
        name = args[0]
        dd = data_dir()
        path = dd / f"{name}.json"
        if path == self.e._path:
            self.err("ese es el engagement abierto ahora. Carga otro o sal primero")
            return
        if not path.exists():
            self.err(f"no existe el engagement '{name}'")
            return
        try:
            resp = input(f"borrar '{name}' para siempre? [y/N] ").strip().lower()
        except EOFError:
            resp = "n"
        if resp != "y":
            self.p("cancelado")
            return
        path.unlink(missing_ok=True)
        (dd / f"{name}.asrep").unlink(missing_ok=True)
        self.ok(f"borrado '{name}'")

    def c_target(self, args):
        if not args:
            self.p(f"host activo: {self.active_host or '(ninguno)'}")
            return
        ip = args[0]
        name = args[1] if len(args) > 1 else ""
        self.e.add_host(ip, hostname=name)
        self.active_host = ip
        self.ok(f"host activo -> {ip}" + (f" ({name})" if name else ""))

    def c_recon(self, args):
        host = args[0] if args else self.active_host
        if not host:
            self.err("no hay host. Usa 'target <ip>' o 'recon <ip>'")
            return
        if not self.runner.available:
            self.err("no encuentro nxc/netexec en el PATH. Arranca con --mock para probar la interfaz.")
            return
        self.active_host = host
        self.p(f"[dim]-- recon sobre {host} --[/dim]" if _RICH else f"-- recon sobre {host} --")
        # si la sesion no se guarda, los AS-REP van a /tmp (disposable)
        asrep = (str(self.asrep_path) if (self.e.keep and self.asrep_path)
                 else "/tmp/arpeggio_asrep.txt")
        summary = recon(self.e, self.runner, host,
                        log=lambda m: self.p(f"[dim]{m}[/dim]" if _RICH else m),
                        asrep_path=asrep)
        self.ok(f"\nListo. Auth que conecto: {', '.join(summary['auth_worked']) or 'ninguna'}  "
                f"usuarios: {summary['users']}  shares: {summary['shares']}  grupos: {summary['groups']}")
        if self.e.lockout_threshold:
            self.warn(f"OJO antes de spray: umbral de bloqueo = {self.e.lockout_threshold}")

    def c_hosts(self, _args):
        if not self.e.hosts:
            self.warn("sin hosts todavia")
            return
        t = self._table("Hosts", ["IP", "Nombre", "Dominio", "SO", "Firma", "SMB", "LDAP"])
        rows = []
        for h in self.e.hosts.values():
            rows.append([h.ip, h.hostname or "-", h.domain or "-", h.os or "-",
                         "si" if h.signing else ("no" if h.signing is False else "?"),
                         "si" if h.smb else "?", "si" if h.ldap else "?"])
        self._emit(t, rows)

    def c_users(self, _args):
        if not self.e.users:
            self.warn("sin usuarios todavia")
            return
        t = self._table(f"Usuarios ({len(self.e.users)})", ["Usuario", "Dominio", "RID", "Origen"])
        rows = [[u.username, u.domain or "-", u.rid if u.rid is not None else "-", u.source or "-"]
                for u in self.e.users.values()]
        self._emit(t, rows)

    def c_creds(self, _args):
        if not self.e.creds:
            self.warn("sin credenciales. Metelas con 'add cred <u> <pass>' o 'add hash <u> <hash>'")
            return
        t = self._table("Credenciales", ["Usuario", "Tipo", "Secreto", "Vale en", "Admin en"])
        rows = []
        for c in self.e.creds:
            secret = c.secret if c.kind == "hash" else (c.secret[:3] + "***" if len(c.secret) > 3 else "***")
            rows.append([f"{c.domain}\\{c.username}" if c.domain else c.username,
                         c.kind, secret,
                         ", ".join(c.valid_on) or "-",
                         ", ".join(c.admin_on) or "-"])
        self._emit(t, rows)

    def c_shares(self, args):
        shares = self.e.shares
        if args:
            shares = [s for s in shares if s.host == args[0]]
        if not shares:
            self.warn("sin shares")
            return
        t = self._table("Shares", ["Host", "Share", "Permisos", "Comentario"])
        rows = [[s.host, s.name, s.permissions or "-", s.remark or ""] for s in shares]
        self._emit(t, rows)

    def c_groups(self, _args):
        if not self.e.groups:
            self.warn("sin grupos")
            return
        t = self._table(f"Grupos ({len(self.e.groups)})", ["Grupo", ""])
        rows = []
        for g in self.e.groups:
            juicy = any(j in g.lower() for j in JUICY_GROUPS)
            mark = "[bold red]<--[/bold red]" if (juicy and _RICH) else ("<--" if juicy else "")
            rows.append([f"[bold]{g}[/bold]" if (juicy and _RICH) else g, mark])
        self._emit(t, rows)

    def c_passpol(self, _args):
        if not self.e.pass_pol:
            self.warn("sin politica de contrasenas (lanza recon o 'nxc smb <ip> --pass-pol')")
            return
        self.p(self.e.pass_pol)
        if self.e.lockout_threshold:
            self.warn(f"\numbral de bloqueo: {self.e.lockout_threshold}")

    def c_add(self, args):
        if len(args) < 2:
            self.err("uso: add host|user|cred|hash ...")
            return
        kind = args[0].lower()
        if kind == "host":
            self.e.add_host(args[1], hostname=args[2] if len(args) > 2 else "")
            self.ok(f"host {args[1]} dado de alta")
        elif kind == "user":
            self.e.add_user(args[1], source="manual")
            self.ok(f"usuario {args[1]} dado de alta")
        elif kind == "cred" and len(args) >= 3:
            self.e.add_cred(args[1], args[2], kind="password")
            self.ok(f"credencial {args[1]} guardada")
        elif kind == "hash" and len(args) >= 3:
            self.e.add_cred(args[1], args[2], kind="hash")
            self.ok(f"hash de {args[1]} guardado")
        else:
            self.err("uso: add host <ip> [n] | add user <u> | add cred <u> <pass> | add hash <u> <hash>")

    def c_spray(self, args):
        proto_arg = (args[0].lower() if args else "smb")
        protos = ["smb", "winrm"] if proto_arg == "all" else [proto_arg]
        if not self.e.creds:
            self.err("no hay credenciales que probar")
            return
        if not self.e.hosts:
            self.err("no hay hosts contra los que probar")
            return
        if not self.runner.available:
            self.err("no encuentro nxc/netexec en el PATH")
            return
        if self.e.lockout_threshold:
            self.warn(f"umbral de bloqueo del dominio: {self.e.lockout_threshold} "
                      f"(spray prueba 1 secreto conocido por usuario, riesgo bajo, pero ojo)")
        for c in self.e.creds:
            for host in list(self.e.hosts):
                for proto in protos:
                    self.p(f"[dim]{proto} {host} {c.username}...[/dim]" if _RICH
                           else f"{proto} {host} {c.username}...")
                    res = self.runner.run(proto, host, c.username, c.secret,
                                          c.kind == "hash", [])
                    self.e.add_run(host, proto.upper(),
                                   f"{c.username}:{c.kind}", "(spray)",
                                   " ".join(res.cmd), res.returncode,
                                   auth_ok(res.output, proto.upper()), res.output)
                    if auth_ok(res.output, proto.upper()):
                        if host not in c.valid_on:
                            c.valid_on.append(host)
                        if parse_pwned(res.output) and host not in c.admin_on:
                            c.admin_on.append(host)
                        tag = "Pwn3d!" if host in c.admin_on else "OK"
                        self.ok(f"  [+] {c.username} entra en {host} ({proto}) {tag}")
        self.e.save()
        self.p("\nspray terminado. Mira 'creds'.")

    def c_log(self, _args):
        if not self.e.runs:
            self.warn("sin comandos lanzados")
            return
        t = self._table("Comandos nxc", ["id", "host", "proto", "auth", "flags", "ok"])
        rows = [[r.id, r.host, r.proto, r.auth, r.flags,
                 "si" if r.success else "-"] for r in self.e.runs[-40:]]
        self._emit(t, rows)
        self.p("[dim]usa 'raw <id>' para ver la salida completa[/dim]" if _RICH
               else "usa 'raw <id>' para ver la salida completa")

    def c_raw(self, args):
        if not args or not args[0].isdigit():
            self.err("uso: raw <id>  (el id sale en 'log')")
            return
        r = self.e.get_run(int(args[0]))
        if not r:
            self.err("no existe ese id")
            return
        self.p(f"[dim]# {r.cmd}[/dim]" if _RICH else f"# {r.cmd}")
        self.p(r.raw or "(sin salida)")


def make_runner(mock: bool) -> Runner:
    if mock:
        from .mockrunner import MockRunner
        return MockRunner()
    return Runner()


def main():
    ap = argparse.ArgumentParser(description="Consola de recon/creds para AD sobre nxc")
    ap.add_argument("name", nargs="?", default=None,
                    help="nombre del engagement (por defecto: la carpeta actual)")
    ap.add_argument("-f", "--file", default=None,
                    help="ruta explicita a un JSON (ignora la carpeta de datos)")
    ap.add_argument("--mock", action="store_true", help="sin nxc, salida de ejemplo")
    args = ap.parse_args()

    dd = data_dir()
    console_path_stem = None
    if args.file:
        path = Path(args.file).expanduser()
        engagement = Engagement.load(path)          # ruta explicita -> se guarda
        console_path_stem = path.stem
    elif args.name:
        path = dd / f"{args.name}.json"
        engagement = Engagement.load(path)          # nombre explicito -> se guarda
        console_path_stem = args.name
    else:
        # sin nombre -> sesion en memoria, no toca disco hasta 'keep'
        engagement = Engagement.in_memory(name=Path.cwd().name or "scratch")

    console = Console(engagement, make_runner(args.mock))
    console.hist_path = dd / "history"
    if console_path_stem:
        console.asrep_path = dd / f"{console_path_stem}.asrep"

    label = engagement.name + ("" if engagement.keep else " [en memoria]")
    banner = f"arpeggio  |  {label}  |  'help' para empezar"
    if args.mock:
        banner += "  [MODO MOCK]"
    console.p(f"[bold cyan]{banner}[/bold cyan]" if _RICH else banner)
    if not console.runner.available and not args.mock:
        console.warn("nxc/netexec no esta en el PATH: recon y spray no funcionaran (instala netexec)")

    if _PTK:
        session = PromptSession(history=FileHistory(str(console.hist_path)),
                                completer=WordCompleter(COMMANDS, ignore_case=True))
        prompt = lambda: session.prompt("arpeggio> ")
    else:
        console.warn("prompt_toolkit no instalado: sin autocompletado ni historial")
        prompt = lambda: input("arpeggio> ")

    while True:
        try:
            line = prompt()
        except (EOFError, KeyboardInterrupt):
            console.p("\nhasta luego")
            break
        if not console.dispatch(line):
            console.p("hasta luego")
            break


if __name__ == "__main__":
    main()
