"""Smoke test sin nxc: valida parsers, ronda de recon, spray y JSON."""
import tempfile
from pathlib import Path

from arpeggio.core import Engagement
from arpeggio.nxcwrap import (recon, parse_shares, parse_rid_brute, parse_users,
                     parse_groups, parse_pass_pol, auth_ok, parse_pwned)
from arpeggio.mockrunner import (MockRunner, _SHARES, _RIDBRUTE, _LDAP_USERS,
                        _GROUPS, _PASSPOL, _SPRAY_OK)

print("== parsers ==")
shares = parse_shares(_SHARES)
assert any(s["name"] == "Data" and "WRITE" in s["permissions"] for s in shares), shares
assert any(s["name"] == "IPC$" and s["permissions"] == "READ" for s in shares), shares
print(f"shares: {[s['name'] for s in shares]}")

rids = parse_rid_brute(_RIDBRUTE)
names = {u["username"] for u in rids}
assert "svc_sql" in names and "jdoe" in names, names
assert "Domain Admins" not in names, "no deberia colar grupos"
assert all(u["rid"] for u in rids)
print(f"rid-brute usuarios: {sorted(names)}")

lusers = parse_users(_LDAP_USERS)
lnames = {u["username"] for u in lusers}
assert {"Administrator", "jdoe", "svc_sql", "mwallace"} <= lnames, lnames
print(f"ldap users: {sorted(lnames)}")

groups = parse_groups(_GROUPS)
assert "Domain Admins" in groups and "Enterprise Admins" in groups, groups
print(f"groups: {groups}")

pol, thr = parse_pass_pol(_PASSPOL)
assert thr == "5", repr(thr)
assert "Minimum password length: 7" in pol
print(f"pass-pol umbral: {thr}")

assert auth_ok(_SHARES, "SMB")
assert parse_pwned(_SPRAY_OK)
print("auth_ok y Pwn3d OK")

print("\n== recon completo (mock) ==")
with tempfile.TemporaryDirectory() as d:
    path = Path(d) / "eng.json"
    e = Engagement.load(path)
    summary = recon(e, MockRunner(), "10.10.11.45", log=lambda m: None)
    print("resumen:", summary)
    assert e.domain == "corp.local", e.domain
    assert len(e.users) >= 4, list(e.users)
    assert any(s.name == "Data" for s in e.shares)
    assert e.lockout_threshold == "5"
    assert "Domain Admins" in e.groups
    assert len(e.runs) > 5

    print("\n== spray (mock) ==")
    e.add_cred("jdoe", "Summer2026!")
    e.add_cred("svc_sql", "wrongpass")
    from arpeggio.cli import Console
    c = Console(e, MockRunner())
    c.out = None  # sin rich para test limpio
    c.c_spray([])
    jdoe = next(x for x in e.creds if x.username == "jdoe")
    assert "10.10.11.45" in jdoe.valid_on, jdoe.valid_on
    assert "10.10.11.45" in jdoe.admin_on, jdoe.admin_on
    svc = next(x for x in e.creds if x.username == "svc_sql")
    assert svc.valid_on == [], svc.valid_on
    print("jdoe valid_on:", jdoe.valid_on, "admin_on:", jdoe.admin_on)

    print("\n== roundtrip JSON ==")
    e2 = Engagement.load(path)
    assert len(e2.users) == len(e.users)
    assert len(e2.creds) == len(e.creds)
    assert e2.lockout_threshold == "5"
    j = next(x for x in e2.creds if x.username == "jdoe")
    assert j.admin_on == ["10.10.11.45"]
    print("recargado OK: usuarios", len(e2.users), "creds", len(e2.creds))

print("\nTODO OK")
