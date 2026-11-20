"""
Data model and storage for arpeggio.

No nxc and no interface here: just the "things" you discover during an
engagement (hosts, users, credentials, shares, and a log of everything
that was launched) and how they are saved to and loaded from a JSON
file. This is the program's memory.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


def data_dir() -> Path:
    """
    The single folder where ALL of arpeggio's state lives.

    Honours XDG_DATA_HOME if set, otherwise ~/.local/share/arpeggio.
    The per-engagement JSON files, the history and the AS-REP hashes all
    land here. Nothing is ever written to the folder you launch from.
    """
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    d = Path(base) / "arpeggio"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _key(username: str, domain: str) -> str:
    """Dedup key for users/credentials, case-insensitive."""
    return f"{(domain or '').lower()}\\{(username or '').lower()}"


@dataclass
class Host:
    ip: str
    hostname: str = ""
    domain: str = ""
    os: str = ""
    signing: Optional[bool] = None       # SMB signing required
    smb: Optional[bool] = None           # answers on SMB
    ldap: Optional[bool] = None          # answers on LDAP
    notes: str = ""


@dataclass
class User:
    username: str
    domain: str = ""
    source: str = ""                     # where it came from: --users, rid-brute, ldap, manual
    rid: Optional[int] = None
    notes: str = ""


@dataclass
class Cred:
    username: str
    secret: str                          # password, or NTLM hash if kind == "hash"
    kind: str = "password"               # "password" | "hash"
    domain: str = ""
    valid_on: list[str] = field(default_factory=list)   # IPs where it authenticates
    admin_on: list[str] = field(default_factory=list)   # IPs where it is admin (Pwn3d)
    notes: str = ""


@dataclass
class Share:
    host: str                            # host IP
    name: str
    permissions: str = ""
    remark: str = ""


@dataclass
class Run:
    """An nxc command that was launched, with its full raw output kept."""
    id: int
    ts: str
    host: str
    proto: str
    auth: str                            # readable label: null, guest, user:pass...
    flags: str
    cmd: str
    returncode: int
    success: bool
    raw: str


class Engagement:
    """All the state of one job. Autosaves after every change."""

    def __init__(self, name: str = "default", path: Optional[Path] = None):
        self.name = name
        self.keep = False                # False = in-memory session, never touches disk
        self.domain = ""                 # "main" domain once detected
        self.created = _now()
        self.hosts: dict[str, Host] = {}
        self.users: dict[str, User] = {}
        self.creds: list[Cred] = []
        self.shares: list[Share] = []
        self.groups: list[str] = []
        self.pass_pol: str = ""          # password policy text
        self.lockout_threshold: Optional[str] = None
        self.runs: list[Run] = []
        self._run_counter = 0
        self._path = path
        self._autosave = True

    # ---- inserts / merge (everything goes through here to dedup and autosave) ----

    def add_host(self, ip: str, **kw) -> Host:
        h = self.hosts.get(ip)
        if h is None:
            h = Host(ip=ip)
            self.hosts[ip] = h
        for k, v in kw.items():
            if v not in (None, "") and hasattr(h, k):
                setattr(h, k, v)
        if h.domain and not self.domain:
            self.domain = h.domain
        self.save()
        return h

    def add_user(self, username: str, domain: str = "", source: str = "",
                 rid: Optional[int] = None) -> User:
        if not username:
            return None
        k = _key(username, domain or self.domain)
        u = self.users.get(k)
        if u is None:
            u = User(username=username, domain=domain or self.domain, source=source, rid=rid)
            self.users[k] = u
        else:
            if source and source not in u.source:
                u.source = (u.source + "," + source).strip(",")
            if rid is not None and u.rid is None:
                u.rid = rid
        self.save()
        return u

    def add_cred(self, username: str, secret: str, kind: str = "password",
                 domain: str = "") -> Cred:
        domain = domain or self.domain
        for c in self.creds:
            if (_key(c.username, c.domain) == _key(username, domain)
                    and c.secret == secret and c.kind == kind):
                return c
        c = Cred(username=username, secret=secret, kind=kind, domain=domain)
        self.creds.append(c)
        self.save()
        return c

    def add_share(self, host: str, name: str, permissions: str = "", remark: str = "") -> Share:
        for s in self.shares:
            if s.host == host and s.name == name:
                if permissions:
                    s.permissions = permissions
                if remark:
                    s.remark = remark
                self.save()
                return s
        s = Share(host=host, name=name, permissions=permissions, remark=remark)
        self.shares.append(s)
        self.save()
        return s

    def add_groups(self, names: list[str]):
        for n in names:
            if n and n not in self.groups:
                self.groups.append(n)
        self.save()

    def add_run(self, host: str, proto: str, auth: str, flags: str, cmd: str,
                returncode: int, success: bool, raw: str) -> Run:
        self._run_counter += 1
        r = Run(id=self._run_counter, ts=_now(), host=host, proto=proto, auth=auth,
                flags=flags, cmd=cmd, returncode=returncode, success=success, raw=raw)
        self.runs.append(r)
        self.save()
        return r

    def get_run(self, run_id: int) -> Optional[Run]:
        for r in self.runs:
            if r.id == run_id:
                return r
        return None

    # ---- serialization ----

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "keep": self.keep,
            "domain": self.domain,
            "created": self.created,
            "run_counter": self._run_counter,
            "pass_pol": self.pass_pol,
            "lockout_threshold": self.lockout_threshold,
            "groups": self.groups,
            "hosts": {ip: asdict(h) for ip, h in self.hosts.items()},
            "users": {k: asdict(u) for k, u in self.users.items()},
            "creds": [asdict(c) for c in self.creds],
            "shares": [asdict(s) for s in self.shares],
            "runs": [asdict(r) for r in self.runs],
        }

    @classmethod
    def from_dict(cls, d: dict, path: Optional[Path] = None) -> "Engagement":
        e = cls(name=d.get("name", "default"), path=path)
        e.keep = d.get("keep", True)     # if it is on disk, default to permanent
        e.domain = d.get("domain", "")
        e.created = d.get("created", _now())
        e._run_counter = d.get("run_counter", 0)
        e.pass_pol = d.get("pass_pol", "")
        e.lockout_threshold = d.get("lockout_threshold")
        e.groups = d.get("groups", [])
        e.hosts = {ip: Host(**h) for ip, h in d.get("hosts", {}).items()}
        e.users = {k: User(**u) for k, u in d.get("users", {}).items()}
        e.creds = [Cred(**c) for c in d.get("creds", [])]
        e.shares = [Share(**s) for s in d.get("shares", [])]
        e.runs = [Run(**r) for r in d.get("runs", [])]
        return e

    # ---- disk ----

    def save(self):
        if not self._autosave or self._path is None:
            return
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))
        tmp.replace(self._path)

    @classmethod
    def load(cls, path: Path) -> "Engagement":
        if path.exists():
            data = json.loads(path.read_text())
            e = cls.from_dict(data, path=path)
            e._path = path
            return e
        e = cls(name=path.stem, path=path)
        e.keep = True
        e.save()
        return e

    @classmethod
    def in_memory(cls, name: str = "scratch") -> "Engagement":
        """A session that does NOT touch disk. Promoted with keep()."""
        e = cls(name=name, path=None)
        e.keep = False
        e._autosave = False
        return e


def list_engagements(dd: Optional[Path] = None) -> list[dict]:
    """
    List the saved engagements in the data folder without loading them
    fully: just enough for the `engagements` command.
    """
    dd = dd or data_dir()
    out = []
    for p in sorted(dd.glob("*.json")):
        if p.name.endswith(".tmp"):
            continue
        try:
            d = json.loads(p.read_text())
        except Exception:  # noqa: BLE001
            continue
        age_h = (time.time() - p.stat().st_mtime) / 3600.0
        out.append({
            "name": d.get("name", p.stem),
            "path": p,
            "hosts": len(d.get("hosts", {})),
            "users": len(d.get("users", {})),
            "creds": len(d.get("creds", [])),
            "age_h": age_h,
            "updated": time.strftime("%Y-%m-%d %H:%M",
                                     time.localtime(p.stat().st_mtime)),
        })
    return out
