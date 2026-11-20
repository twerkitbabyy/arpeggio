"""
Runner falso que devuelve salida de nxc de ejemplo, para probar la
interfaz y los parsers sin nxc ni maquinas. Arranca con:  --mock

La salida imita el formato real de netexec (DC de un dominio ficticio).
"""

from __future__ import annotations

from .nxcwrap import RawResult

IP = "10.10.11.45"
HOST = "DC01"
DOM = "corp.local"

_HOSTLINE = f"SMB         {IP}    445    {HOST}"
_LDAPLINE = f"LDAP        {IP}    389    {HOST}"

_LOGIN_OK = (
    f"{_HOSTLINE}           [*] Windows Server 2019 Build 17763 x64 "
    f"(name:{HOST}) (domain:{DOM}) (signing:True) (SMBv1:False)\n"
    f"{_HOSTLINE}           [+] {DOM}\\guest: \n"
)

_SHARES = _LOGIN_OK + (
    f"{_HOSTLINE}           [*] Enumerated shares\n"
    f"{_HOSTLINE}           Share           Permissions     Remark\n"
    f"{_HOSTLINE}           -----           -----------     ------\n"
    f"{_HOSTLINE}           ADMIN$                          Remote Admin\n"
    f"{_HOSTLINE}           C$                              Default share\n"
    f"{_HOSTLINE}           IPC$            READ            Remote IPC\n"
    f"{_HOSTLINE}           NETLOGON        READ            Logon server share \n"
    f"{_HOSTLINE}           SYSVOL          READ            Logon server share \n"
    f"{_HOSTLINE}           Data            READ,WRITE      \n"
)

_USERS_EMPTY = _LOGIN_OK  # --users no devuelve nada util -> fuerza rid-brute

_RIDBRUTE = _LOGIN_OK + (
    f"{_HOSTLINE}           498: {DOM.split('.')[0].upper()}\\Enterprise Read-only Domain Controllers (SidTypeGroup)\n"
    f"{_HOSTLINE}           500: {DOM.split('.')[0].upper()}\\Administrator (SidTypeUser)\n"
    f"{_HOSTLINE}           501: {DOM.split('.')[0].upper()}\\Guest (SidTypeUser)\n"
    f"{_HOSTLINE}           1000: {DOM.split('.')[0].upper()}\\DC01$ (SidTypeUser)\n"
    f"{_HOSTLINE}           1103: {DOM.split('.')[0].upper()}\\svc_sql (SidTypeUser)\n"
    f"{_HOSTLINE}           1104: {DOM.split('.')[0].upper()}\\jdoe (SidTypeUser)\n"
    f"{_HOSTLINE}           1105: {DOM.split('.')[0].upper()}\\Domain Admins (SidTypeGroup)\n"
)

_GROUPS = _LOGIN_OK + (
    f"{_HOSTLINE}           [+] Enumerated domain group(s)\n"
    f"{_HOSTLINE}           Domain Admins                    membercount: 2\n"
    f"{_HOSTLINE}           Domain Users                     membercount: 12\n"
    f"{_HOSTLINE}           Enterprise Admins                membercount: 1\n"
    f"{_HOSTLINE}           IT Support                       membercount: 4\n"
)

_PASSPOL = _LOGIN_OK + (
    f"{_HOSTLINE}           [+] Dumping password info for domain: {DOM.split('.')[0].upper()}\n"
    f"{_HOSTLINE}           Minimum password length: 7\n"
    f"{_HOSTLINE}           Password history length: 24\n"
    f"{_HOSTLINE}           Maximum password age: 42 days\n"
    f"{_HOSTLINE}           Account Lockout Threshold: 5\n"
    f"{_HOSTLINE}           Reset Account Lockout Counter: 30 minutes\n"
)

_LDAP_USERS = (
    f"{_LDAPLINE}           [+] {DOM}\\guest: \n"
    f"{_LDAPLINE}           [*] Enumerated domain user(s)\n"
    f"{_LDAPLINE}           {DOM}\\Administrator\n"
    f"{_LDAPLINE}           {DOM}\\jdoe\n"
    f"{_LDAPLINE}           {DOM}\\svc_sql\n"
    f"{_LDAPLINE}           {DOM}\\mwallace\n"
)

_LDAP_ASREP = (
    f"{_LDAPLINE}           [+] {DOM}\\guest: \n"
    f"{_LDAPLINE}           [*] Total of records returned 1\n"
    f"{_LDAPLINE}           $krb5asrep$23$svc_sql@{DOM.upper()}:abc123...\n"
)

_SPRAY_OK = (
    f"{_HOSTLINE}           [*] Windows Server 2019 (name:{HOST}) (domain:{DOM})\n"
    f"{_HOSTLINE}           [+] {DOM}\\jdoe:Summer2026! (Pwn3d!)\n"
)
_SPRAY_FAIL = (
    f"{_HOSTLINE}           [*] Windows Server 2019 (name:{HOST}) (domain:{DOM})\n"
    f"{_HOSTLINE}           [-] {DOM}\\svc_sql:wrongpass STATUS_LOGON_FAILURE\n"
)


class MockRunner:
    available = True

    def run(self, proto, host, user, secret, is_hash, flags) -> RawResult:
        cmd = ["nxc", proto, host, "-u", user, "-H" if is_hash else "-p", secret] + flags
        f = " ".join(flags)

        if proto == "ldap":
            out = _LDAP_ASREP if "--asreproast" in flags else _LDAP_USERS
            return RawResult(cmd=cmd, returncode=0, output=out)

        if not flags:
            # login simple o spray
            if secret in ("", None) or user in ("", "guest"):
                return RawResult(cmd=cmd, returncode=0, output=_LOGIN_OK)
            out = _SPRAY_OK if (user == "jdoe" and secret == "Summer2026!") else _SPRAY_FAIL
            return RawResult(cmd=cmd, returncode=0, output=out)

        if "--shares" in flags:
            out = _SHARES
        elif "--rid-brute" in flags:
            out = _RIDBRUTE
        elif "--users" in flags:
            out = _USERS_EMPTY
        elif "--groups" in flags:
            out = _GROUPS
        elif "--pass-pol" in flags:
            out = _PASSPOL
        else:
            out = _LOGIN_OK
        return RawResult(cmd=cmd, returncode=0, output=out)
