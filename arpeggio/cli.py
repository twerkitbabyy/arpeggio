#!/usr/bin/env python3
"""
arpeggio - interactive console for Active Directory recon and credentials.

The idea: keep it open during a box or a prolab, run `recon`, and
everything it finds (users, shares, password policy, domain) is kept
inside. When you find a credential you add it with `add`, and `spray`
tests it against every host at once, marking where it works and where
you are admin.

Usage:
    python3 -m arpeggio                 # in-memory session (named after cwd)
    python3 -m arpeggio dante           # engagement 'dante'
    python3 -m arpeggio --mock          # no nxc, sample output (demo/tests)

Inside, type `help`.
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
except ImportError:                      # degrade gracefully if rich is missing
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
Commands:
  status                      quick summary of the engagement
  where                       paths / whether this session is being saved
  keep [name]                 keep: from now on the session is saved to disk
  engagements                 list the saved engagements
  load <name>                 load a saved engagement
  forget <name>               delete a saved engagement
  target <ip> [name]          set the active host (and register it)
  recon [ip]                  full null+guest round, SMB+LDAP (active host if no ip)
  hosts                       discovered hosts
  users                       discovered users
  creds                       credentials and where they work
  shares [ip]                 shares (all, or for one host)
  groups                      domain groups (juicy ones highlighted)
  passpol                     password policy / lockout threshold
  add host <ip> [name]        add a host manually
  add user <user>             add a user manually
  add cred <user> <pass>      add a credential (password)
  add hash <user> <hash>      add a credential (NTLM hash)
  spray [smb|winrm|all]       test EVERY cred against EVERY host
  log                         nxc commands that were launched
  raw <id>                    raw output of a command (id from `log`)
  save                        force a save (it autosaves anyway)
  clear                       clear the screen
  exit / quit                 leave
"""

JUICY_GROUPS = ("domain admins", "enterprise admins", "administrators",
                "schema admins", "backup operators", "account operators",
                "dnsadmins", "remote desktop users")


class Console:
    """State + command logic. Kept apart from the REPL so it can be tested."""

    def __init__(self, engagement: Engagement, runner: Runner):
        self.e = engagement
        self.runner = runner
        self.active_host: str | None = None
        self.out = RichConsole() if _RICH else None
        # helper paths (filled by main); used by 'where' and recon
        self.hist_path: Path | None = None
        self.asrep_path: Path | None = None

    # ---- print helpers ----

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
        """Run one line. Returns False to exit the REPL."""
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
            "save": lambda a: (self.e.save(), self.ok("saved")),
            "clear": lambda a: (self.out.clear() if _RICH else None),
        }.get(cmd)

        if cmd in ("exit", "quit"):
            return False
        if handler is None:
            self.err(f"unknown command: {cmd}  (type 'help')")
            return True
        handler(args)
        return True

    # ---- commands ----

    def c_help(self, _args):
        self.p(HELP)

    def c_status(self, _args):
        self.p(f"[bold]{self.e.name}[/bold]  domain: {self.e.domain or '?'}  "
               f"active: {self.active_host or '-'}" if _RICH else
               f"{self.e.name}  domain: {self.e.domain or '?'}  active: {self.active_host or '-'}")
        self.p(f"hosts: {len(self.e.hosts)}   users: {len(self.e.users)}   "
               f"creds: {len(self.e.creds)}   shares: {len(self.e.shares)}   "
               f"commands: {len(self.e.runs)}")
        self.p("saved: YES" if self.e.keep else
               "saved: NO (memory only; 'keep <name>' to persist)")
        if self.e.lockout_threshold:
            self.warn(f"lockout threshold: {self.e.lockout_threshold}")

    def c_where(self, _args):
        if not self.e.keep:
            self.warn("this session is NOT being saved (memory only)")
            self.p("Use 'keep <name>' to persist it from now on.")
            self.p(f"\nIf you save it, it would go to: {data_dir()}")
            return
        self.p("This session is saved. Everything lives in one place:")
        self.p(f"  data folder      : {data_dir()}")
        self.p(f"  engagement (JSON): {self.e._path}")
        if self.hist_path:
            self.p(f"  history          : {self.hist_path}")
        if self.asrep_path:
            self.p(f"  AS-REP hashes    : {self.asrep_path}")
        self.p("\nNothing is written to the folder you launch from.")

    def c_keep(self, args):
        name = args[0] if args else self.e.name
        dd = data_dir()
        path = dd / f"{name}.json"
        if path.exists() and path != self.e._path:
            self.err(f"engagement '{name}' already exists. Use 'load {name}' or pick another name")
            return
        self.e.name = name
        self.e.keep = True
        self.e._path = path
        self.e._autosave = True
        self.asrep_path = dd / f"{name}.asrep"
        self.e.save()
        self.ok(f"kept. From now on it is saved to {path}")

    def c_engagements(self, _args):
        items = list_engagements()
        if not items:
            self.warn("no saved engagements yet")
            return
        t = self._table("Saved engagements",
                        ["Name", "Hosts", "Users", "Creds", "Updated"])
        rows = [[it["name"], it["hosts"], it["users"], it["creds"], it["updated"]]
                for it in items]
        self._emit(t, rows)
        self.p("[dim]use 'load <name>' to load one[/dim]" if _RICH
               else "use 'load <name>' to load one")

    def c_load(self, args):
        if not args:
            self.err("usage: load <name>  (see 'engagements')")
            return
        dd = data_dir()
        path = dd / f"{args[0]}.json"
        if not path.exists():
            self.err(f"engagement '{args[0]}' does not exist")
            return
        self.e.save()                    # save the current one if it was kept
        self.e = Engagement.load(path)
        self.asrep_path = dd / f"{path.stem}.asrep"
        self.active_host = None
        self.ok(f"loaded '{self.e.name}'")
        self.c_status([])

    def c_forget(self, args):
        if not args:
            self.err("usage: forget <name>")
            return
        name = args[0]
        dd = data_dir()
        path = dd / f"{name}.json"
        if path == self.e._path:
            self.err("that engagement is open right now. Load another or exit first")
            return
        if not path.exists():
            self.err(f"engagement '{name}' does not exist")
            return
        try:
            resp = input(f"delete '{name}' for good? [y/N] ").strip().lower()
        except EOFError:
            resp = "n"
        if resp != "y":
            self.p("cancelled")
            return
        path.unlink(missing_ok=True)
        (dd / f"{name}.asrep").unlink(missing_ok=True)
        self.ok(f"deleted '{name}'")

    def c_target(self, args):
        if not args:
            self.p(f"active host: {self.active_host or '(none)'}")
            return
        ip = args[0]
        name = args[1] if len(args) > 1 else ""
        self.e.add_host(ip, hostname=name)
        self.active_host = ip
        self.ok(f"active host -> {ip}" + (f" ({name})" if name else ""))

    def c_recon(self, args):
        host = args[0] if args else self.active_host
        if not host:
            self.err("no host. Use 'target <ip>' or 'recon <ip>'")
            return
        if not self.runner.available:
            self.err("nxc/netexec not found in PATH. Start with --mock to try the interface.")
            return
        self.active_host = host
        self.p(f"[dim]-- recon on {host} --[/dim]" if _RICH else f"-- recon on {host} --")
        # if the session is not saved, AS-REP hashes go to /tmp (disposable)
        asrep = (str(self.asrep_path) if (self.e.keep and self.asrep_path)
                 else "/tmp/arpeggio_asrep.txt")
        summary = recon(self.e, self.runner, host,
                        log=lambda m: self.p(f"[dim]{m}[/dim]" if _RICH else m),
                        asrep_path=asrep)
        self.ok(f"\nDone. Auth that worked: {', '.join(summary['auth_worked']) or 'none'}  "
                f"users: {summary['users']}  shares: {summary['shares']}  groups: {summary['groups']}")
        if self.e.lockout_threshold:
            self.warn(f"HEADS UP before spray: lockout threshold = {self.e.lockout_threshold}")

    def c_hosts(self, _args):
        if not self.e.hosts:
            self.warn("no hosts yet")
            return
        t = self._table("Hosts", ["IP", "Name", "Domain", "OS", "Signing", "SMB", "LDAP"])
        rows = []
        for h in self.e.hosts.values():
            rows.append([h.ip, h.hostname or "-", h.domain or "-", h.os or "-",
                         "yes" if h.signing else ("no" if h.signing is False else "?"),
                         "yes" if h.smb else "?", "yes" if h.ldap else "?"])
        self._emit(t, rows)

    def c_users(self, _args):
        if not self.e.users:
            self.warn("no users yet")
            return
        t = self._table(f"Users ({len(self.e.users)})", ["User", "Domain", "RID", "Source"])
        rows = [[u.username, u.domain or "-", u.rid if u.rid is not None else "-", u.source or "-"]
                for u in self.e.users.values()]
        self._emit(t, rows)

    def c_creds(self, _args):
        if not self.e.creds:
            self.warn("no credentials. Add them with 'add cred <u> <pass>' or 'add hash <u> <hash>'")
            return
        t = self._table("Credentials", ["User", "Type", "Secret", "Valid on", "Admin on"])
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
            self.warn("no shares")
            return
        t = self._table("Shares", ["Host", "Share", "Permissions", "Remark"])
        rows = [[s.host, s.name, s.permissions or "-", s.remark or ""] for s in shares]
        self._emit(t, rows)

    def c_groups(self, _args):
        if not self.e.groups:
            self.warn("no groups")
            return
        t = self._table(f"Groups ({len(self.e.groups)})", ["Group", ""])
        rows = []
        for g in self.e.groups:
            juicy = any(j in g.lower() for j in JUICY_GROUPS)
            mark = "[bold red]<--[/bold red]" if (juicy and _RICH) else ("<--" if juicy else "")
            rows.append([f"[bold]{g}[/bold]" if (juicy and _RICH) else g, mark])
        self._emit(t, rows)

    def c_passpol(self, _args):
        if not self.e.pass_pol:
            self.warn("no password policy yet (run recon or 'nxc smb <ip> --pass-pol')")
            return
        self.p(self.e.pass_pol)
        if self.e.lockout_threshold:
            self.warn(f"\nlockout threshold: {self.e.lockout_threshold}")

    def c_add(self, args):
        if len(args) < 2:
            self.err("usage: add host|user|cred|hash ...")
            return
        kind = args[0].lower()
        if kind == "host":
            self.e.add_host(args[1], hostname=args[2] if len(args) > 2 else "")
            self.ok(f"host {args[1]} added")
        elif kind == "user":
            self.e.add_user(args[1], source="manual")
            self.ok(f"user {args[1]} added")
        elif kind == "cred" and len(args) >= 3:
            self.e.add_cred(args[1], args[2], kind="password")
            self.ok(f"credential {args[1]} saved")
        elif kind == "hash" and len(args) >= 3:
            self.e.add_cred(args[1], args[2], kind="hash")
            self.ok(f"hash for {args[1]} saved")
        else:
            self.err("usage: add host <ip> [n] | add user <u> | add cred <u> <pass> | add hash <u> <hash>")

    def c_spray(self, args):
        proto_arg = (args[0].lower() if args else "smb")
        protos = ["smb", "winrm"] if proto_arg == "all" else [proto_arg]
        if not self.e.creds:
            self.err("no credentials to test")
            return
        if not self.e.hosts:
            self.err("no hosts to test against")
            return
        if not self.runner.available:
            self.err("nxc/netexec not found in PATH")
            return
        if self.e.lockout_threshold:
            self.warn(f"domain lockout threshold: {self.e.lockout_threshold} "
                      f"(spray tests 1 known secret per user, low risk, but watch out)")
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
                        self.ok(f"  [+] {c.username} works on {host} ({proto}) {tag}")
        self.e.save()
        self.p("\nspray done. Check 'creds'.")

    def c_log(self, _args):
        if not self.e.runs:
            self.warn("no commands launched")
            return
        t = self._table("nxc commands", ["id", "host", "proto", "auth", "flags", "ok"])
        rows = [[r.id, r.host, r.proto, r.auth, r.flags,
                 "yes" if r.success else "-"] for r in self.e.runs[-40:]]
        self._emit(t, rows)
        self.p("[dim]use 'raw <id>' to see the full output[/dim]" if _RICH
               else "use 'raw <id>' to see the full output")

    def c_raw(self, args):
        if not args or not args[0].isdigit():
            self.err("usage: raw <id>  (the id comes from 'log')")
            return
        r = self.e.get_run(int(args[0]))
        if not r:
            self.err("no such id")
            return
        self.p(f"[dim]# {r.cmd}[/dim]" if _RICH else f"# {r.cmd}")
        self.p(r.raw or "(no output)")


def make_runner(mock: bool) -> Runner:
    if mock:
        from .mockrunner import MockRunner
        return MockRunner()
    return Runner()


def main():
    ap = argparse.ArgumentParser(description="Interactive AD recon/creds console on top of nxc")
    ap.add_argument("name", nargs="?", default=None,
                    help="engagement name (default: the current folder)")
    ap.add_argument("-f", "--file", default=None,
                    help="explicit path to a JSON (ignores the data folder)")
    ap.add_argument("--mock", action="store_true", help="no nxc, sample output")
    args = ap.parse_args()

    dd = data_dir()
    console_path_stem = None
    if args.file:
        path = Path(args.file).expanduser()
        engagement = Engagement.load(path)          # explicit path -> saved
        console_path_stem = path.stem
    elif args.name:
        path = dd / f"{args.name}.json"
        engagement = Engagement.load(path)          # explicit name -> saved
        console_path_stem = args.name
    else:
        # no name -> in-memory session, does not touch disk until 'keep'
        engagement = Engagement.in_memory(name=Path.cwd().name or "scratch")

    console = Console(engagement, make_runner(args.mock))
    console.hist_path = dd / "history"
    if console_path_stem:
        console.asrep_path = dd / f"{console_path_stem}.asrep"

    label = engagement.name + ("" if engagement.keep else " [in memory]")
    banner = f"arpeggio  |  {label}  |  type 'help' to start"
    if args.mock:
        banner += "  [MOCK MODE]"
    console.p(f"[bold cyan]{banner}[/bold cyan]" if _RICH else banner)
    if not console.runner.available and not args.mock:
        console.warn("nxc/netexec not in PATH: recon and spray will not work (install netexec)")

    if _PTK:
        session = PromptSession(history=FileHistory(str(console.hist_path)),
                                completer=WordCompleter(COMMANDS, ignore_case=True))
        prompt = lambda: session.prompt("arpeggio> ")
    else:
        console.warn("prompt_toolkit not installed: no autocomplete or history")
        prompt = lambda: input("arpeggio> ")

    while True:
        try:
            line = prompt()
        except (EOFError, KeyboardInterrupt):
            console.p("\nbye")
            break
        if not console.dispatch(line):
            console.p("bye")
            break


if __name__ == "__main__":
    main()
