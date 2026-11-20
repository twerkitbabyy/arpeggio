# arpeggio

Interactive console for Active Directory recon and credential management,
built on top of [netexec](https://github.com/Pennant/NetExec) (nxc).

You keep it open during a box or a prolab. You run `recon` against a host
and all the credential-less enumeration (null + guest session, SMB +
LDAP) is kept inside the program. When you find a credential you add it
with `add`, and `spray` tests it against every host at once, marking
where it works and where you are admin. Saved engagements autosave to a
per-engagement JSON, so you can close it and pick up tomorrow.

It was born from one specific chore: not having to type the 6+ recon
commands (`--shares`, `--users`, `--rid-brute`, `--pass-pol`...) by hand
with a null session **and** with guest every time you land on a machine.

## Installation

```bash
git clone https://github.com/twerkitbabyy/arpeggio
cd arpeggio
./install.sh
```

`install.sh` creates its own isolated environment (it does not touch your
system packages, which Arch appreciates), installs arpeggio inside it and
drops the `arpeggio` command in `~/.local/bin`. Open a new terminal and
you can call it from any folder. If `~/.local/bin` is not in your PATH,
the script warns you and gives you the line to add to `~/.zshrc`.

To uninstall: `./uninstall.sh` (it does not delete your saved engagements).

It needs `nxc`/`netexec` separately in your PATH for `recon` and `spray`
(`pipx install netexec`). Without them the rest of the console works
fine, and you have `--mock`.

You can also run it without installing, straight from the repo:

```bash
python3 -m pip install rich prompt_toolkit
python3 -m arpeggio
```

## Persistence: nothing is saved by default

arpeggio starts **in memory**. Until you say otherwise it writes nothing
to disk: you do a simple box, close it, and no trace is left.

When you want to keep a session (e.g. a prolab like Dante), inside the
console:

```
arpeggio> keep dante        # from here on it is saved, under the name 'dante'
```

From that point it autosaves. The next day, even after a reboot:

```
arpeggio> engagements       # lists what is saved -> 'dante' shows up here
arpeggio> load dante        # loads it exactly as you left it
arpeggio> forget dante      # when you no longer want it, deletes it (asks to confirm)
```

Everything saved lives in **one folder**: `~/.local/share/arpeggio/`
(or `$XDG_DATA_HOME/arpeggio`). Nothing is ever written to the folder you
launch from. Inside, for each kept engagement:

| file | what it is |
|---|---|
| `<name>.json` | the engagement (hosts, users, creds, shares, raw output) |
| `<name>.asrep` | AS-REP hashes from recon, ready to crack |
| `history` | the console command history (a single file, like the shell's) |

The `where` command tells you at any moment whether the session is being
saved and where. To start fresh: `rm -rf ~/.local/share/arpeggio/`.

## Usage

```bash
arpeggio              # in-memory session (not saved until you run 'keep')
arpeggio dante        # open/create the already-kept engagement 'dante'
arpeggio -f /path/x.json   # a JSON at a specific path, if you need it
arpeggio --mock       # no nxc, sample output (to play around)
```

Inside, `help` lists everything. Typical flow:

```
arpeggio> target 10.10.11.45 DC01    # set the active host
arpeggio> recon                      # full null+guest round, SMB+LDAP
arpeggio> users                      # what it found
arpeggio> shares
arpeggio> passpol                    # MIND the lockout threshold before spraying
arpeggio> add cred jdoe 'Summer2026!'
arpeggio> add hash administrator aad3b4...:31d6cfe0d16ae931b73c59d7e0c089c0
arpeggio> spray all                  # test every cred against every host (smb+winrm)
arpeggio> creds                      # where they work and where you are admin (Pwn3d)
```

### What `recon` does

On the host:

1. Tries a **null** and a **guest** SMB session, and keeps whichever connect(s).
2. Under that auth it runs: `--pass-pol`, `--shares`, `--users`, `--groups`, `--loggedon-users`, `--sessions`.
3. If `--users` comes back empty, it falls back to `--rid-brute` automatically.
4. Tries **LDAP with an anonymous bind** (`--users` and `--asreproast`), which sometimes hands out users even with SMB closed.

Everything goes into the store, and the raw output of each command is
kept (`log` for the list, `raw <id>` to see it in full). If netexec
changes some format and parsing fails, you never lose the info: the raw
text is still there.

## Layout

```
arpeggio/
  install.sh / uninstall.sh   isolated installer + command in ~/.local/bin
  pyproject.toml              package and dependencies (entry point 'arpeggio')
  arpeggio/
    cli.py        the interactive console and the tables
    core.py       data model (Host, User, Cred, Share, Run) and JSON storage
    nxcwrap.py    nxc runner, parsers and the recon-round orchestration
    mockrunner.py fake runner with sample output for --mock and the tests
  tests/
    test_smoke.py tests parsers, recon, spray and JSON roundtrip without nxc
```

The nxc logic is kept apart from the interface on purpose: if one day you
want it with real panels (Textual), you only touch `cli.py`.

## Notes

- Tool for authorized labs and engagements.
- `spray` tests **one** known secret per user, not a wordlist, so the
  lockout risk is low; it still reminds you of the domain lockout
  threshold if it saw one in `--pass-pol`.
