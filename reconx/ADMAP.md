# admap — AD attack-path assistant

`admap` is the step *after* ReconX. Where `recon` tells you **what is on a
box**, `admap` answers **"given what I now hold, what Active Directory attack
paths are open, and exactly what do I run next?"**

It models the [Orange Cyberdefense AD mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg)
as a state machine keyed on your current level of access and prints a **ranked,
already-filled-in playbook** — the target, user, and domain are substituted in,
so every command is copy-paste ready.

```
no credentials  →  username(s)  →  valid creds  →  local admin  →  domain dominance
```

It is a single stdlib-only Python file (`admap.py`) plus a launcher (`admap`),
same design rules as ReconX: Python 3.8+, no third-party imports, every
external tool optional with a graceful "missing: X" note.

## Technique tags — what admap will and won't run

| Tag | Meaning | `--run` |
|-----|---------|---------|
| `[ENUM]`   | read-only identification (null sessions, RID-brute, BloodHound collect, Kerberoast/AS-REP *request*, certipy *find*, LDAP property mining) | **auto-runnable** |
| `[SPRAY]`  | touches authentication — password spraying, lockout risk | printed, never auto-run |
| `[MANUAL]` | exploitation / post-exploitation / domain dominance (relay, ACL abuse, SAM/LSASS dump, psexec, DCSync, golden ticket) | printed only |

`--run` executes **only `[ENUM]` steps**, saves each tool's output, flags
confirmed hits, and uses them to unlock and re-rank deeper techniques (e.g. a
validated cred that returns `(Pwn3d!)` flips you into the local-admin phase).
This mirrors the project rule and OSCP tool policy: **enumeration is automated,
exploitation stays in your hands.**

## Usage

```bash
# No creds yet — outsider playbook against the DC
admap dc01 --anon

# Username list from RID-brute — spray / AS-REP targets
admap dc01 -d corp.local --users users.txt

# Valid domain creds — full authenticated playbook AND run the read-only enum
admap dc01 -d corp.local -u alex -p 'Passw0rd!' --dc-ip <dc-ip> --run

# Pass-the-hash, already local admin on a member host
admap ms01 -u administrator -H <lm:nt> --local-admin

# Just print the plan, run nothing; or show the entire catalog
admap dc01 -d corp.local -u alex -p 'pw' --dry-run
admap dc01 --all
```

`TARGET` accepts an IP/host **or** a var name that `setup_pentest_env` exports
(`dc01 ms01 ms02 t1 t2 t3 ip1..`), exactly like `recon`.

### Key flags

| Flag | Meaning |
|------|---------|
| `--anon` | you hold no credentials (default when none given) |
| `-u / -p / -H` | username / password / NT or `LM:NT` hash (PtH) |
| `-d --domain`, `--dc-ip` | domain FQDN and DC address (DC defaults to the target) |
| `--users FILE` | username list for spray / AS-REP / kerbrute |
| `--local-auth` | treat the credential as a **local** account, not domain |
| `--local-admin` | assert you're already local admin → unlocks phase 3 (dumping) |
| `--domain-admin` | assert DA / DCSync rights → unlocks phase 4 |
| `--run` | auto-run the `[ENUM]` steps (read-only) and re-rank on results |
| `--dry-run` | print only (default) |
| `--all` | print the full catalog regardless of state |
| `-o DIR` | output directory (the launcher points this at `scans/admap/`) |
| `--timeout N` | per-command timeout for `--run` (default 300s) |

## Output

Run via the `admap` launcher inside a box workspace and everything lands flat
under `scans/admap/` (same convention as ReconX's single-host `--workspace`):

```
<box>/scans/admap/
├── ad_playbook.md          # the ranked playbook as Markdown (regenerated after --run)
├── admap_rid-brute.txt     # saved output, one file per executed [ENUM] step
├── admap_cred-validate.txt
└── …
```

`ad_playbook.md` drops straight into your Obsidian box note alongside ReconX's
findings.

## The mindmap phases

- **Phase 0 — no creds:** SMB null/guest, RID-brute, LDAP anonymous bind,
  enum4linux-ng, rpcclient, DNS/SRV, AS-REP (no-preauth), kerbrute userenum,
  pre2k; plus `[MANUAL]` Responder / ntlmrelayx / coercion.
- **Phase 1 — username(s):** read the password policy first, lockout-aware
  spray `[SPRAY]`, AS-REP roast.
- **Phase 2 — valid creds:** validate + find where you're admin, BloodHound,
  Kerberoast, AS-REP, share spidering, GPP cpassword, LDAP property mining,
  **LAPS** and **gMSA** password reads, Certipy ADCS `find`, delegation enum,
  MachineAccountQuota read, MSSQL access/priv/link enum; `[MANUAL]` hashcat,
  ACL-edge abuse, **Shadow Credentials** (msDS-KeyCredentialLink → PKINIT →
  UnPAC-the-hash), ADCS ESC exploitation, **RBCD** (addcomputer → rbcd → getST
  → psexec), **unconstrained** (coerce → capture DC TGT) and **constrained**
  (S4U getST) delegation abuse, **noPac** (CVE-2021-42278/42287), **MSSQL →
  RCE** (xp_cmdshell / EXECUTE AS / linked servers).
- **Phase 3 — local admin:** `[MANUAL]` SAM/LSA + LSASS + DPAPI dump, lateral
  movement (psexec/wmiexec/evil-winrm).
- **Phase 4 — domain dominance:** `[MANUAL]` DCSync / NTDS, golden ticket.

## Extending the catalog

Each node is a `Tech(...)` in `build_catalog()`:

```python
Tech("tid", PHASE, "name", KIND, prio, "mindmap > branch > leaf",
     "one-line why",
     when=lambda st: st.have_creds,              # precondition over State
     cmd=lambda st: f"certipy find -u {st.user} …",  # filled-in command
     tool="certipy",                              # availability check
     success=re.compile(r"ESC\d+"))               # marks a confirmed hit
```

Add a node, give it a precondition and a command template, and it slots into
the right phase automatically. `success` is what `--run` greps for to call a
step confirmed and (optionally) mutate `State` in `_learn()`.

## Exam-rules note

`admap` orchestrates standard enumeration tools and **prints** exploitation
commands for you to run by hand — it performs no automated exploitation and no
mass vulnerability scanning, keeping it in the same OSCP-policy category as
ReconX and AutoRecon. Authorized targets only (your lab, HTB/PG/THM, or the
exam). Always confirm against the current official OSCP Exam Guide before your
attempt.
