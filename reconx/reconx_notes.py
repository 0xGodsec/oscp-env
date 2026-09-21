#!/usr/bin/env python3
"""
reconx_notes - Obsidian / PakCyberbot notes integration for reconx.

Two jobs, both stdlib-only:

  1. enrich_host_notes()  - a richer per-host NOTES.md than reconx's built-in:
     YAML frontmatter, a host-profile callout, the ports table, *wikilinks*
     into your methodology vault picked from the open services, ranked
     findings and suggested next steps. Drop-in for write_markdown().

  2. build_exam_note()    - generates/refreshes ONE exam-wide note in your
     Obsidian vault, shaped like the PakCyberbot "Network Pentest Template"
     (CREDS.txt block, Hashes, per-Machine sections, Attack Narrative). Recon
     data lives inside marker-delimited "managed blocks"; everything you type
     by hand (creds, foothold story, flags) sits OUTSIDE those markers and is
     never overwritten on refresh.

reconx.py imports this lazily and falls back to its built-in NOTES.md if the
module is missing, so the single-file tool still runs standalone.
"""

import os
import re
from datetime import datetime

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

# --------------------------------------------------------------------------- #
#  Vault discovery
# --------------------------------------------------------------------------- #
def default_vault():
    """Env RECONX_VAULT wins; else ~/Desktop/Notes if it's a real dir; else
    None (caller then skips vault writes)."""
    env = os.environ.get("RECONX_VAULT")
    if env and os.path.isdir(os.path.expanduser(env)):
        return os.path.expanduser(env)
    guess = os.path.expanduser("~/Desktop/Notes")
    return guess if os.path.isdir(guess) else None


# --------------------------------------------------------------------------- #
#  Service -> methodology wikilinks
#
#  Note names below match the vault's 02-Services / 03-Initial Access /
#  04-05-06 privesc + AD files, so every [[link]] resolves.
# --------------------------------------------------------------------------- #
_PORT_LINKS = {
    21: ["FTP"], 22: ["SSH"], 23: ["Telnet"], 25: ["SMTP"],
    53: ["DNS"], 79: ["Finger"], 88: ["Kerberos", "AS-REP Roasting", "Kerberoasting"],
    110: ["POP3 IMAP"], 111: ["NFS", "RPC"], 135: ["RPC"], 139: ["SMB"],
    143: ["POP3 IMAP"], 161: ["SNMP"], 389: ["LDAP", "AD Enumeration"],
    443: ["HTTPS", "Web Exploitation"], 445: ["SMB"], 465: ["SMTP"],
    587: ["SMTP"], 636: ["LDAP", "AD Enumeration"], 993: ["POP3 IMAP"],
    995: ["POP3 IMAP"], 1433: ["MSSQL"], 1521: ["Oracle TNS"], 2049: ["NFS"],
    3268: ["LDAP", "AD Enumeration"], 3269: ["LDAP"], 3306: ["MySQL"],
    3389: ["RDP"], 5432: ["PostgreSQL"], 5900: ["VNC"], 5985: ["WinRM"],
    5986: ["WinRM"], 6379: ["Redis"], 27017: ["MongoDB"],
}
# common web ports -> HTTP note
for _wp in (80, 81, 591, 2082, 3000, 5000, 8000, 8008, 8080, 8081, 8180,
            8443, 8888, 9000, 9090):
    _PORT_LINKS.setdefault(_wp, ["HTTP", "Web Exploitation"])

_NAME_LINKS = {
    "http": ["HTTP", "Web Exploitation"], "https": ["HTTPS", "Web Exploitation"],
    "ssl/http": ["HTTPS", "Web Exploitation"], "smb": ["SMB"],
    "microsoft-ds": ["SMB"], "netbios-ssn": ["SMB"], "ldap": ["LDAP", "AD Enumeration"],
    "kerberos": ["Kerberos", "AS-REP Roasting", "Kerberoasting"], "ftp": ["FTP"],
    "ssh": ["SSH"], "smtp": ["SMTP"], "domain": ["DNS"], "snmp": ["SNMP"],
    "mssql": ["MSSQL"], "ms-sql-s": ["MSSQL"], "mysql": ["MySQL"],
    "postgresql": ["PostgreSQL"], "oracle": ["Oracle TNS"], "redis": ["Redis"],
    "mongodb": ["MongoDB"], "rdp": ["RDP"], "ms-wbt-server": ["RDP"],
    "winrm": ["WinRM"], "wsman": ["WinRM"], "nfs": ["NFS"], "rpcbind": ["RPC", "NFS"],
    "msrpc": ["RPC"], "pop3": ["POP3 IMAP"], "imap": ["POP3 IMAP"],
    "telnet": ["Telnet"], "vnc": ["VNC"], "finger": ["Finger"],
}

_HOST_TYPE_LINKS = {
    "linux": ["Linux Privilege Escalation", "Linux Credential Hunting"],
    "windows": ["Windows Privilege Escalation", "Windows Stored Credentials"],
    "ad": ["Active Directory", "AD Enumeration", "BloodHound", "Kerberoasting"],
    "web": ["Web Exploitation"],
}


def service_links(services, host_profile=None):
    """Ordered, de-duped list of [[wikilink]] strings for the open services
    + host archetype. `services` is {port: {'name':.., 'version':..}}."""
    out = []

    def push(names):
        for n in names:
            link = f"[[{n}]]"
            if link not in out:
                out.append(link)

    for port in sorted(services):
        meta = services[port] or {}
        name = (meta.get("name") or "").lower()
        if port in _PORT_LINKS:
            push(_PORT_LINKS[port])
        for key, links in _NAME_LINKS.items():
            if key in name:
                push(links)
                break
    ht = (host_profile or {}).get("host_type")
    if (host_profile or {}).get("dc_signals", 0) >= 2:
        ht = "ad"
    if ht in _HOST_TYPE_LINKS:
        push(_HOST_TYPE_LINKS[ht])
    return out


def _host_type_of(host_profile):
    if (host_profile or {}).get("dc_signals", 0) >= 2:
        return "ad"
    return (host_profile or {}).get("host_type")


_HOST_TYPE_LABELS = {
    "ad": "Active Directory host / likely Domain Controller",
    "windows": "Windows host", "linux": "Linux host", "web": "web-focused host",
}


def _findings_rows(findings):
    uniq = {}
    for f in findings:
        if hasattr(f, "sev"):
            key = (f.sev, f.service, f.port, f.text)
        elif isinstance(f, (list, tuple)) and len(f) >= 4:
            key = (f[0], f[1], f[2], f[3])
        else:
            continue
        uniq[key] = None
    return sorted(uniq, key=lambda t: (SEV_ORDER.get(t[0], 9), t[2] or 0))


# --------------------------------------------------------------------------- #
#  1. Enriched per-host NOTES.md
# --------------------------------------------------------------------------- #
def enrich_host_notes(host, services, udp, findings, host_profile, outdir,
                      next_steps=None, host_dir=None):
    # host_dir overrides the default <outdir>/<host> layout (reconx passes it in
    # --workspace/flat mode so notes land directly under scans/reconx/).
    path = os.path.join(host_dir or os.path.join(outdir, host), "NOTES.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ht = _host_type_of(host_profile)
    links = service_links(services, host_profile)

    with open(path, "w") as f:
        # frontmatter
        f.write("---\n")
        f.write(f"target: {host}\n")
        f.write(f"date: {datetime.now():%Y-%m-%d}\n")
        f.write(f"host_type: {ht or 'unknown'}\n")
        f.write("tags: [reconx, recon"
                + (f", {ht}" if ht else "") + "]\n")
        f.write("---\n\n")

        f.write(f"# recon - {host}\n\n_generated {datetime.now():%Y-%m-%d %H:%M} by reconx_\n\n")
        label = _HOST_TYPE_LABELS.get(ht)
        if label:
            f.write(f"> [!info] Host profile\n> likely **{label}**.\n\n")

        f.write("## Open TCP ports\n\n| Port | Service | Version |\n|---|---|---|\n")
        for p in sorted(services):
            m = services[p] or {}
            f.write(f"| {p} | {m.get('name','')} | {m.get('version','')} |\n")
        if udp:
            f.write("\n## Open UDP ports\n\n| Port | Service |\n|---|---|\n")
            for p in sorted(udp):
                f.write(f"| {p} | {udp[p]} |\n")

        if links:
            f.write("\n## Methodology links\n\n")
            f.write(" ".join(links) + "\n")

        f.write("\n## Ranked findings\n\n")
        rows = _findings_rows(findings)
        if rows:
            for sev, svc, port, text in rows:
                tag = f"{svc}{':'+str(port) if port else ''}"
                f.write(f"- **{sev}** `{tag}` - {text}\n")
        else:
            f.write("_none surfaced yet_\n")

        if next_steps:
            f.write("\n## Suggested next steps\n\n")
            for s in next_steps:
                f.write(f"- {s}\n")

        f.write("\n## To do\n\n- [ ] \n")
    return path


# --------------------------------------------------------------------------- #
#  2. Vault exam note (managed blocks)
# --------------------------------------------------------------------------- #
def _block_re(key):
    s = re.escape(f"<!-- reconx:auto:start:{key} -->")
    e = re.escape(f"<!-- reconx:auto:end:{key} -->")
    return re.compile(s + r".*?" + e, re.S)


def _wrap(key, body):
    return (f"<!-- reconx:auto:start:{key} -->\n{body}\n"
            f"<!-- reconx:auto:end:{key} -->")


def _replace_block(text, key, body):
    """Replace the managed block for `key` in-place. Returns (text, True) if a
    block existed, else (text, False)."""
    pat = _block_re(key)
    wrapped = _wrap(key, body)
    if pat.search(text):
        return pat.sub(lambda _m: wrapped, text), True
    return text, False


def _machine_auto_body(t, results_dir=None):
    """The recon summary reconx owns inside each Machine section."""
    from_status = t.get("status", "todo")
    lines = []
    lines.append(f"> [!note] reconx recon  ·  **{from_status.upper()}**  ·  "
                 f"{t.get('points', 0)} pts  ·  OS: {t.get('os') or '?'}")
    ports = t.get("ports") or []
    if ports:
        lines.append("")
        lines.append("**Open ports:** " + ", ".join(f"`{p}`" for p in ports))
    # wikilinks from ports
    fake_services = {int(p): {"name": ""} for p in ports}
    links = service_links(fake_services, {"host_type": t.get("os")})
    if links:
        lines.append("")
        lines.append("**Playbooks:** " + " ".join(links))
    tf = t.get("top_findings") or []
    if tf:
        lines.append("")
        lines.append("**Top findings:**")
        for sev, svc, port, txt in tf:
            tag = f"{svc}{':'+str(port) if port else ''}"
            lines.append(f"- **{sev}** `{tag}` - {txt}")
    if results_dir:
        rp = os.path.join(results_dir, t["ip"])
        lines.append("")
        lines.append(f"_raw output:_ `{rp}`")
    return "\n".join(lines)


def _new_machine_section(t, results_dir=None):
    """Full scaffold for a machine that doesn't exist in the note yet:
    heading + anchor + managed block + manual (user-owned) subsections."""
    ip = t["ip"]
    return (
        f"\n# {t.get('label', 'Machine')} - IP: {ip}  <!-- reconx:machine:{ip} -->\n"
        f"{_wrap('machine:' + ip, _machine_auto_body(t, results_dir))}\n\n"
        "## Enumeration (scratch)\n```shell\n\n```\n\n"
        "## 🚪 Initial Foothold\n- How I got in:\n\n"
        "### Machine Enumerated Data\n```shell\n\n```\n\n"
        "## Potential PrivEsc vectors\n\n"
        "## ⬆ Privilege Escalation\n- How I escalated:\n\n"
        "## Flags\n- [ ] local.txt\n- [ ] proof.txt\n"
    )


def _scaffold(data, results_dir=None):
    name = data["name"]
    created = (data.get("created_at") or "")[:10] or datetime.now().strftime("%Y-%m-%d")
    parts = []
    parts.append("---\n"
                 f"title: {name}\n"
                 f"date: {created}\n"
                 f"machines: {len(data['targets'])}\n"
                 "tags: [oscp, exam, reconx]\n"
                 "---\n")
    parts.append("# 🧭 reconx Dashboard\n"
                 + _wrap("dashboard", "_dashboard will populate on next scan / refresh_")
                 + "\n")
    parts.append(
        "# 🗄 CREDS.txt\n```\n\n```\n"
        "## Hashes\n```\n# Domain accounts\n\n# Local Accounts\n\n```\n"
        "## Personal Notes\n```\n\n```\n"
        "## Path or CheckPoint\n\n"
        "# 🗃 Active Directory Domain Info\n```\n\n```\n"
    )
    for t in sorted(data["targets"].values(), key=lambda x: x.get("order", 0)):
        parts.append(_new_machine_section(t, results_dir))
    parts.append("\n# Attack Narrative\n\n")
    return "\n".join(parts)


def build_exam_note(data, results_dir=None):
    """Create or refresh the vault exam note at data['vault_note'].

    - First time: write the full scaffold.
    - Refresh: update the dashboard + each machine's managed block, append
      sections for any newly-added machines, and bump the frontmatter machine
      count - touching nothing the user typed between the markers.
    """
    try:
        import reconx_exam
    except ImportError:
        reconx_exam = None

    note = data.get("vault_note")
    if not note:
        return None
    note = os.path.expanduser(note)
    os.makedirs(os.path.dirname(note) or ".", exist_ok=True)

    board_md = (reconx_exam.render_board_markdown(data)
                if reconx_exam else "_(reconx_exam unavailable)_")

    if not os.path.isfile(note):
        text = _scaffold(data, results_dir)
        text, _ = _replace_block(text, "dashboard", board_md)
        with open(note, "w") as f:
            f.write(text)
        return note

    with open(note) as f:
        text = f.read()

    # dashboard
    text, ok = _replace_block(text, "dashboard", board_md)
    if not ok:  # user deleted it - re-inject near top
        text = re.sub(r"(^#\s.*\n)", r"\1" + _wrap("dashboard", board_md) + "\n",
                      text, count=1, flags=re.M) or (_wrap("dashboard", board_md) + "\n" + text)

    # machines
    for t in sorted(data["targets"].values(), key=lambda x: x.get("order", 0)):
        ip = t["ip"]
        body = _machine_auto_body(t, results_dir)
        text, ok = _replace_block(text, "machine:" + ip, body)
        if not ok:
            section = _new_machine_section(t, results_dir)
            if "# Attack Narrative" in text:
                text = text.replace("# Attack Narrative", section + "\n# Attack Narrative", 1)
            else:
                text += "\n" + section

    # frontmatter machine count
    text = re.sub(r"(?m)^machines:\s*\d+\s*$", f"machines: {len(data['targets'])}", text, count=1)

    with open(note, "w") as f:
        f.write(text)
    return note


# --------------------------------------------------------------------------- #
#  3. PakCyberbot workspace integration
#
#  Fill the per-box `notes.md` that `setup_pentest_env` scaffolds, IN PLACE and
#  non-destructively: header fields (IP/OS/Date) only when blank, Ports/Services
#  rows deduped by port (never clobbering a row you edited), and a single
#  marker-delimited "ReconX findings" block that refreshes on re-run. Everything
#  you type by hand is left untouched. Reuses PakCyberbot's template - it does
#  NOT create a competing notes file.
# --------------------------------------------------------------------------- #
_PCB_OS_LABEL = {"ad": "Windows (Active Directory)", "windows": "Windows",
                 "linux": "Linux", "web": "Linux/Unix (web)"}


def _fill_header_field(text, field, value):
    """Set '- **Field:** <value>' only if it's currently empty."""
    pat = re.compile(rf"(?m)^(- \*\*{re.escape(field)}:\*\*)[ \t]*$")
    if pat.search(text):
        return pat.sub(lambda _m: f"- **{field}:** {value}", text, count=1)
    return text


def _merge_ports_table(text, services):
    """Append a row per open port under the '## Ports / Services' table,
    skipping ports already present (so hand-added/edited rows survive)."""
    lines = text.splitlines()
    # find the table separator line inside the Ports/Services section
    sep_idx = None
    in_section = False
    for i, ln in enumerate(lines):
        if ln.strip().startswith("## Ports"):
            in_section = True
            continue
        if in_section and re.match(r"^\|\s*-{2,}", ln):
            sep_idx = i
            break
        if in_section and ln.startswith("## "):
            break  # section ended before a table - bail
    if sep_idx is None:
        return text  # template not as expected; leave it alone

    # gather existing data rows + the ports they already list
    end = sep_idx + 1
    existing_ports = set()
    while end < len(lines) and lines[end].lstrip().startswith("|"):
        cells = [c.strip() for c in lines[end].strip().strip("|").split("|")]
        if cells and cells[0].isdigit():
            existing_ports.add(int(cells[0]))
        end += 1

    new_rows = []
    for port in sorted(services):
        if port in existing_ports:
            continue
        m = services[port] or {}
        name = m.get("name", "") or ""
        ver = m.get("version", "") or ""
        links = " ".join(service_links({port: {"name": name}})) or ""
        new_rows.append(f"| {port} | {name} | {ver} | {links} |")
    if not new_rows:
        return text
    lines[end:end] = new_rows
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _reconx_block_body(host, services, udp, findings, host_profile, rel_dir, next_steps):
    ht = _host_type_of(host_profile)
    links = service_links(services, host_profile)
    out = []
    label = _HOST_TYPE_LABELS.get(ht)
    out.append(f"### ReconX findings — {host}")
    out.append(f"_auto-filled {datetime.now():%Y-%m-%d %H:%M} · full output: `{rel_dir}`_")
    if label:
        out.append(f"- **Host profile:** likely {label}")
    ports = ", ".join(f"`{p}`" for p in sorted(services))
    if ports:
        out.append(f"- **Open TCP:** {ports}")
    if udp:
        out.append("- **Open UDP:** " + ", ".join(f"`{p}`" for p in sorted(udp)))
    if links:
        out.append("- **Playbooks:** " + " ".join(links))
    rows = _findings_rows(findings)
    if rows:
        out.append("")
        out.append("**Ranked findings (look first):**")
        for sev, svc, port, txt in rows:
            tag = f"{svc}{':'+str(port) if port else ''}"
            out.append(f"- **{sev}** `{tag}` — {txt}")
    if next_steps:
        out.append("")
        out.append("**Suggested next steps:**")
        for s in next_steps:
            out.append(f"- {s}")
    return "\n".join(out)


def merge_workspace_notes(notes_path, host, services, udp, findings, host_profile,
                          reconx_dir, next_steps=None):
    """Merge ReconX results into a PakCyberbot per-box notes.md, in place.
    `reconx_dir` is the absolute path to this host's ReconX output; the link
    written into notes.md is made relative to the notes file when possible."""
    if not os.path.isfile(notes_path):
        return None
    with open(notes_path) as f:
        text = f.read()

    # header fields (only if blank)
    text = _fill_header_field(text, "IP", host)
    ht = _host_type_of(host_profile)
    if ht and _PCB_OS_LABEL.get(ht):
        text = _fill_header_field(text, "OS", _PCB_OS_LABEL[ht])
    text = _fill_header_field(text, "Date", datetime.now().strftime("%Y-%m-%d"))

    # ports table
    text = _merge_ports_table(text, services)

    # managed findings block (idempotent) - placed before Foothold section
    try:
        rel_dir = os.path.relpath(reconx_dir, os.path.dirname(notes_path))
    except ValueError:
        rel_dir = reconx_dir
    body = _reconx_block_body(host, services, udp, findings, host_profile,
                              rel_dir, next_steps)
    key = f"findings:{host}"
    new_text, replaced = _replace_block(text, key, body)
    if replaced:
        text = new_text
    else:
        block = _wrap(key, body)
        if "## Foothold" in text:
            text = text.replace("## Foothold", block + "\n\n## Foothold", 1)
        else:
            text = text.rstrip() + "\n\n" + block + "\n"

    with open(notes_path, "w") as f:
        f.write(text)
    return notes_path
