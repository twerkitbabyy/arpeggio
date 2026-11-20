"""
The layer that talks to nxc (netexec).

Two jobs:
  1. Launch nxc and capture the output (runner).
  2. Make sense of that output (parsers) and orchestrate the recon round.

Golden rule: the raw output is ALWAYS stored in the engagement. Parsing
is best-effort; if netexec changes a format tomorrow, you never lose the
info because the raw text is still there (the `raw` command).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def find_nxc() -> str | None:
    """Locate the binary: nxc first, then netexec."""
    for name in ("nxc", "netexec"):
        path = shutil.which(name)
        if path:
            return path
    return None


@dataclass
class RawResult:
    cmd: list[str]
    returncode: int
    output: str          # stdout + stderr, already stripped of color codes


class Runner:
    """Launches the real nxc. Injectable: tests swap in one with fixtures."""

    def __init__(self, binary: str | None = None, timeout: int = 120):
        self.binary = binary or find_nxc()
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return self.binary is not None

    def run(self, proto: str, host: str, user: str, secret: str,
            is_hash: bool, flags: list[str]) -> RawResult:
        args = [self.binary, proto, host, "-u", user]
        args += ["-H", secret] if is_hash else ["-p", secret]
        args += flags
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=self.timeout
            )
            out = _strip_ansi((proc.stdout or "") + (proc.stderr or ""))
            return RawResult(cmd=args, returncode=proc.returncode, output=out)
        except subprocess.TimeoutExpired:
            return RawResult(cmd=args, returncode=-1,
                             output=f"[arpeggio] timeout after {self.timeout}s")
        except Exception as exc:  # noqa: BLE001
            return RawResult(cmd=args, returncode=-1, output=f"[arpeggio] error: {exc}")


# ---------------------------------------------------------------------------
# Parsers (they work on text that is already ANSI-free)
# ---------------------------------------------------------------------------

# A line looks like:  SMB  10.10.11.45  445  DC01  <content>
_LINE = re.compile(
    r"^(?P<proto>SMB|LDAP|WINRM|MSSQL|SSH|RDP|FTP|WMI)\s+"
    r"(?P<ip>\S+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+(?P<content>.*)$"
)


def _contents(text: str):
    """Yield (proto, ip, hostname, content) for each nxc line."""
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if m:
            yield m.group("proto"), m.group("ip"), m.group("name"), m.group("content").rstrip()


def auth_ok(text: str, proto: str = "SMB") -> bool:
    """True if there is a [+] (valid authentication) on any line of the protocol."""
    for p, _ip, _n, content in _contents(text):
        if p == proto and content.lstrip().startswith("[+]"):
            return True
    return False


def parse_host_info(text: str) -> dict:
    """Pull out hostname, domain, OS and whether SMB signing is required."""
    info = {}
    for proto, _ip, name, content in _contents(text):
        if proto != "SMB":
            continue
        if content.startswith("[*]"):
            if name and name != "None":
                info["hostname"] = name
            m = re.search(r"\(name:([^)]+)\)", content)
            if m:
                info["hostname"] = m.group(1)
            m = re.search(r"\(domain:([^)]+)\)", content)
            if m:
                info["domain"] = m.group(1)
            m = re.search(r"\(signing:(True|False)\)", content)
            if m:
                info["signing"] = (m.group(1) == "True")
            m = re.search(r"\[\*\]\s*(Windows[^(]+)", content)
            if m:
                info["os"] = m.group(1).strip()
    return info


def parse_shares(text: str) -> list[dict]:
    """Shares: they appear after the Share/Permissions/Remark header."""
    shares, in_table = [], False
    for proto, _ip, _n, content in _contents(text):
        if proto != "SMB":
            continue
        low = content.lower()
        if low.startswith("share") and "permission" in low:
            in_table = True
            continue
        if content.startswith("-----"):
            continue
        if in_table:
            if not content.strip() or content.startswith("[") or low.startswith("enumerated"):
                in_table = False
                continue
            cols = re.split(r"\s{2,}", content.strip())
            name = cols[0] if cols else ""
            perms = cols[1] if len(cols) > 1 else ""
            remark = cols[2] if len(cols) > 2 else ""
            # With only 2 columns it is usually permissions that is missing, not remark
            if len(cols) == 2 and not re.search(r"READ|WRITE", perms, re.I):
                perms, remark = "", cols[1]
            if name:
                shares.append({"name": name, "permissions": perms, "remark": remark})
    return shares


def parse_users(text: str) -> list[dict]:
    """Users from `--users`: lines with DOMAIN\\user after the header."""
    users, started = [], False
    for proto, _ip, _n, content in _contents(text):
        if proto not in ("SMB", "LDAP"):
            continue
        if "enumerated domain user" in content.lower() or "enumerated" in content.lower() and "user" in content.lower():
            started = True
            continue
        if started or "\\" in content:
            m = re.search(r"([^\s\\]+)\\([^\s]+)", content)
            if m and not content.lstrip().startswith("["):
                dom, user = m.group(1), m.group(2)
                if user.lower() not in ("permissions", "share"):
                    users.append({"username": user, "domain": dom, "source": "--users"})
    return _dedupe_users(users)


def parse_rid_brute(text: str) -> list[dict]:
    """Users from `--rid-brute`: only the SidTypeUser entries matter."""
    users = []
    for _proto, _ip, _n, content in _contents(text):
        m = re.match(r"(\d+):\s+([^\\]+)\\([^\s]+)\s+\(SidType(\w+)\)", content)
        if m and m.group(4) == "User":
            rid, dom, user = int(m.group(1)), m.group(2), m.group(3)
            users.append({"username": user, "domain": dom, "source": "rid-brute", "rid": rid})
    return _dedupe_users(users)


def parse_groups(text: str) -> list[str]:
    """Group names from `--groups` (keeps the name, ignores the member count)."""
    groups, started = [], False
    for proto, _ip, _n, content in _contents(text):
        if proto != "SMB":
            continue
        if "enumerated domain group" in content.lower():
            started = True
            continue
        if started and content and not content.lstrip().startswith("["):
            m = re.match(r"([^\s].*?)\s+membercount:", content)
            name = m.group(1).strip() if m else content.strip()
            if name:
                groups.append(name)
    return groups


def parse_pass_pol(text: str) -> tuple[str, str | None]:
    """Return (full policy text, lockout threshold if found)."""
    lines, threshold = [], None
    for proto, _ip, _n, content in _contents(text):
        if proto != "SMB":
            continue
        if "dumping password info" in content.lower() or any(
            kw in content.lower() for kw in (
                "minimum password", "password history", "maximum password age",
                "minimum password age", "account lockout", "locked account",
                "reset account", "password complexity", "password properties",
            )
        ):
            lines.append(content.strip())
        m = re.search(r"Account Lockout Threshold:\s*(.+)", content, re.I)
        if m:
            threshold = m.group(1).strip()
    return "\n".join(lines), threshold


def parse_pwned(text: str) -> bool:
    """True if nxc marks (Pwn3d!): local admin with that credential."""
    return "Pwn3d!" in text


def _dedupe_users(users: list[dict]) -> list[dict]:
    seen, out = set(), []
    for u in users:
        k = (u["domain"].lower(), u["username"].lower())
        if k not in seen:
            seen.add(k)
            out.append(u)
    return out


# ---------------------------------------------------------------------------
# Orchestration: the recon "round"
# ---------------------------------------------------------------------------

# Each step: (label, list of flags). Applied under whichever auth connects.
SMB_STEPS = [
    ("pass-pol", ["--pass-pol"]),
    ("shares", ["--shares"]),
    ("users", ["--users"]),
    ("groups", ["--groups"]),
    ("loggedon", ["--loggedon-users"]),
    ("sessions", ["--sessions"]),
]
# (the LDAP steps are built inside recon() because asreproast needs an
#  output path that depends on the engagement)

# Credential-less auth combos: (label, user, secret)
ANON_AUTH = [
    ("null", "", ""),
    ("guest", "guest", ""),
]


def recon(engagement, runner: Runner, host: str, log=lambda *_: None,
          asrep_path: str = "/tmp/arpeggio_asrep.txt") -> dict:
    """
    Run the full round against `host` and dump everything into the engagement.

    log(msg) is a callback to report progress, so the console can show it
    live. asrep_path is where nxc writes any AS-REP hashes it finds.

    Returns a small summary to print at the end.
    """
    ldap_steps = [
        ("ldap-users", ["--users"]),
        ("asreproast", ["--asreproast", asrep_path]),
    ]
    summary = {"host": host, "auth_worked": [], "users": 0, "shares": 0,
               "groups": 0, "pass_pol": False}

    # Step 0: check which auths connect (and grab host info along the way).
    working = []
    for label, user, secret in ANON_AUTH:
        log(f"[{host}] trying {label} session...")
        res = runner.run("smb", host, user, secret, False, [])
        ok = auth_ok(res.output, "SMB")
        engagement.add_run(host, "SMB", label, "(login)", " ".join(res.cmd),
                           res.returncode, ok, res.output)
        info = parse_host_info(res.output)
        if info:
            engagement.add_host(host, smb=True, **info)
        if ok:
            working.append((label, user, secret))
            summary["auth_worked"].append(label)
            log(f"[{host}] {label} session OK")

    if not working:
        log(f"[{host}] neither null nor guest connect over SMB; continuing with anonymous LDAP")

    # SMB steps under each auth that connected.
    for label, user, secret in working:
        for step, flags in SMB_STEPS:
            log(f"[{host}] {label} {step}...")
            res = runner.run("smb", host, user, secret, False, flags)
            engagement.add_run(host, "SMB", label, " ".join(flags),
                               " ".join(res.cmd), res.returncode,
                               auth_ok(res.output, "SMB"), res.output)
            _absorb(engagement, host, step, res.output, summary)

        # Fallback: if --users found nobody, fall back to rid-brute.
        if summary["users"] == 0:
            log(f"[{host}] {label} --users came back empty, trying --rid-brute...")
            res = runner.run("smb", host, user, secret, False, ["--rid-brute"])
            engagement.add_run(host, "SMB", label, "--rid-brute",
                               " ".join(res.cmd), res.returncode,
                               auth_ok(res.output, "SMB"), res.output)
            for u in parse_rid_brute(res.output):
                engagement.add_user(**u)
                summary["users"] += 1

    # Anonymous LDAP (sometimes hands out users even when SMB is closed).
    for step, flags in ldap_steps:
        log(f"[{host}] ldap-anon {step}...")
        res = runner.run("ldap", host, "", "", False, flags)
        ok = auth_ok(res.output, "LDAP")
        engagement.add_run(host, "LDAP", "null", " ".join(flags),
                           " ".join(res.cmd), res.returncode, ok, res.output)
        if ok:
            engagement.add_host(host, ldap=True)
        for u in parse_users(res.output):
            u["source"] = step
            engagement.add_user(**u)
            summary["users"] += 1

    summary["users"] = len(engagement.users)
    summary["shares"] = len([s for s in engagement.shares if s.host == host])
    summary["groups"] = len(engagement.groups)
    summary["pass_pol"] = bool(engagement.pass_pol)
    return summary


def _absorb(engagement, host: str, step: str, output: str, summary: dict):
    """Store into the engagement whatever a given step produced."""
    if step == "shares":
        for s in parse_shares(output):
            engagement.add_share(host, s["name"], s["permissions"], s["remark"])
    elif step == "users":
        for u in parse_users(output):
            engagement.add_user(**u)
            summary["users"] += 1
    elif step == "groups":
        engagement.add_groups(parse_groups(output))
    elif step == "pass-pol":
        text, threshold = parse_pass_pol(output)
        if text:
            engagement.pass_pol = text
        if threshold:
            engagement.lockout_threshold = threshold
        engagement.save()
