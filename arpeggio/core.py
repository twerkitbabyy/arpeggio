"""
Modelo de datos y almacenamiento de arpeggio.

Aqui no hay nada de nxc ni de interfaz: solo las "cosas" que vas
descubriendo en un engagement (hosts, usuarios, credenciales, shares,
y un registro de todo lo que se ha lanzado) y como se guardan y cargan
de un JSON. Es la memoria del programa.
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
    Carpeta unica donde vive TODO el estado de arpeggio.

    Respeta XDG_DATA_HOME si lo tienes, si no ~/.local/share/arpeggio.
    Aqui caen los JSON de cada engagement, el historial y los hashes
    AS-REP. Nunca se escribe nada en la carpeta desde la que lanzas.
    """
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    d = Path(base) / "arpeggio"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _key(username: str, domain: str) -> str:
    """Clave para deduplicar usuarios/credenciales, insensible a mayusculas."""
    return f"{(domain or '').lower()}\\{(username or '').lower()}"


@dataclass
class Host:
    ip: str
    hostname: str = ""
    domain: str = ""
    os: str = ""
    signing: Optional[bool] = None       # firma SMB obligatoria
    smb: Optional[bool] = None           # responde a SMB
    ldap: Optional[bool] = None          # responde a LDAP
    notes: str = ""


@dataclass
class User:
    username: str
    domain: str = ""
    source: str = ""                     # de donde salio: --users, rid-brute, ldap, manual
    rid: Optional[int] = None
    notes: str = ""


@dataclass
class Cred:
    username: str
    secret: str                          # contrasena, o hash NTLM si kind == "hash"
    kind: str = "password"               # "password" | "hash"
    domain: str = ""
    valid_on: list[str] = field(default_factory=list)   # IPs donde autentica
    admin_on: list[str] = field(default_factory=list)   # IPs donde es admin (Pwn3d)
    notes: str = ""


@dataclass
class Share:
    host: str                            # IP del host
    name: str
    permissions: str = ""
    remark: str = ""


@dataclass
class Run:
    """Un comando nxc que se lanzo, con su salida cruda guardada entera."""
    id: int
    ts: str
    host: str
    proto: str
    auth: str                            # etiqueta legible: null, guest, user:pass...
    flags: str
    cmd: str
    returncode: int
    success: bool
    raw: str


class Engagement:
    """Todo el estado de un trabajo. Se autoguarda tras cada cambio."""

    def __init__(self, name: str = "default", path: Optional[Path] = None):
        self.name = name
        self.keep = False                # False = sesion en memoria, no toca disco
        self.domain = ""                 # dominio "principal" cuando se detecta
        self.created = _now()
        self.hosts: dict[str, Host] = {}
        self.users: dict[str, User] = {}
        self.creds: list[Cred] = []
        self.shares: list[Share] = []
        self.groups: list[str] = []
        self.pass_pol: str = ""          # texto de la politica de contrasenas
        self.lockout_threshold: Optional[str] = None
        self.runs: list[Run] = []
        self._run_counter = 0
        self._path = path
        self._autosave = True

    # ---- altas / merge (todo pasa por aqui para deduplicar y autoguardar) ----

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

    # ---- serializacion ----

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
        e.keep = d.get("keep", True)     # si esta en disco, por defecto es permanente
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

    # ---- disco ----

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
        """Sesion que NO toca el disco. Se promueve con keep()."""
        e = cls(name=name, path=None)
        e.keep = False
        e._autosave = False
        return e


def list_engagements(dd: Optional[Path] = None) -> list[dict]:
    """
    Lista los engagements guardados en la carpeta de datos, sin cargarlos
    enteros: solo lo justo para el comando `engagements`.
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
