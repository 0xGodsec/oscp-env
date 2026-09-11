#!/usr/bin/env python3
"""
reconx_exam - multi-target OSCP exam manager & time budget for reconx.

A companion module (stdlib only) that turns a pile of per-host scans into an
exam-wide workflow: register the machines you're attacking with their point
values, track each one's status (todo -> recon -> foothold -> root) and the
wall-clock time it took to get there, and see a single ranked dashboard with
your running score and how much of the 23h45m exam clock is left.

reconx.py imports this lazily; if it's missing, reconx still runs - you just
lose `reconx exam ...` and the `--exam` scan hook.

State lives in ~/.reconx/exams/<name>.json (stable regardless of cwd), with
~/.reconx/current pointing at the active exam so bare `reconx exam status`
just works. Nothing here touches a network - it's pure bookkeeping.

Ethics: this only tracks YOUR authorized exam/lab targets.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

# --------------------------------------------------------------------------- #
#  Colours (self-contained so there's no circular import with reconx)
# --------------------------------------------------------------------------- #
class _C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; CY = "\033[36m"; GR = "\033[90m"
    BOLD = "\033[1m"; DIM = "\033[2m"; END = "\033[0m"

    @classmethod
    def strip(cls):
        for k in list(vars(cls)):
            v = getattr(cls, k)
            if isinstance(v, str) and v.startswith("\033"):
                setattr(cls, k, "")


if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    _C.strip()

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #
STATUSES = ("todo", "recon", "foothold", "root")
_STATUS_RANK = {s: i for i, s in enumerate(STATUSES)}
STATUS_EMOJI = {"todo": "⬜", "recon": "\U0001f50d",
                "foothold": "⏳", "root": "✅"}
STATUS_COLOR = {"todo": _C.DIM, "recon": _C.CY,
                "foothold": _C.Y, "root": _C.G}

# OSCP exam clock is 23h 45m of hacking time.
DEFAULT_BUDGET_SECS = 23 * 3600 + 45 * 60
DEFAULT_PASS_MARK = 70
DEFAULT_POINTS = 20

_HOME = os.path.expanduser("~/.reconx")
_EXAM_DIR = os.path.join(_HOME, "exams")
_CURRENT = os.path.join(_HOME, "current")

_ISO = "%Y-%m-%d %H:%M:%S"


# --------------------------------------------------------------------------- #
#  Small helpers
# --------------------------------------------------------------------------- #
def _now():
    return datetime.now().strftime(_ISO)


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.strptime(ts, _ISO)
    except (ValueError, TypeError):
        return None


def _secs_between(a, b):
    da, db = _parse(a), _parse(b)
    if not da or not db:
        return None
    return max(0, (db - da).total_seconds())


def fmt_hms(secs):
    if secs is None:
        return "--:--"
    secs = int(secs)
    neg = secs < 0
    secs = abs(secs)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    out = f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:d}:{s:02d}"
    return ("-" + out) if neg else out


def parse_duration(text):
    """'23h45m', '90m', '3600', '2h' -> seconds. Returns None on garbage."""
    if text is None:
        return None
    text = str(text).strip().lower()
    if text.isdigit():
        return int(text)
    total, num = 0, ""
    unit = {"h": 3600, "m": 60, "s": 1}
    for ch in text:
        if ch.isdigit():
            num += ch
        elif ch in unit and num:
            total += int(num) * unit[ch]
            num = ""
        else:
            return None
    if num:  # trailing bare number -> seconds
        total += int(num)
    return total or None


def _emsg(msg):
    print(f"{_C.R}[exam]{_C.END} {msg}", file=sys.stderr)


def _omsg(msg):
    print(f"{_C.G}[exam]{_C.END} {msg}")


# --------------------------------------------------------------------------- #
#  Persistence
# --------------------------------------------------------------------------- #
def _slug(name):
    return "".join(c if (c.isalnum() or c in "-_.") else "-" for c in name).strip("-") or "exam"


def _path_for(name):
    return os.path.join(_EXAM_DIR, _slug(name) + ".json")


def current_exam_name():
    if os.path.isfile(_CURRENT):
        try:
            with open(_CURRENT) as f:
                n = f.read().strip()
            return n or None
        except OSError:
            return None
    return None


def set_current(name):
    os.makedirs(_HOME, exist_ok=True)
    with open(_CURRENT, "w") as f:
        f.write(name)


def exam_exists(name):
    return name and os.path.isfile(_path_for(name))


def load_exam(name=None):
    """Load an exam by name, or the current one if name is None. Returns the
    dict, or None if nothing resolves."""
    if name is None:
        name = current_exam_name()
    if not name or not os.path.isfile(_path_for(name)):
        return None
    try:
        with open(_path_for(name)) as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        _emsg(f"could not read exam '{name}': {e}")
        return None
    data.setdefault("targets", {})
    data.setdefault("budget_secs", DEFAULT_BUDGET_SECS)
    data.setdefault("pass_mark", DEFAULT_PASS_MARK)
    return data


def save_exam(data):
    os.makedirs(_EXAM_DIR, exist_ok=True)
    p = _path_for(data["name"])
    tmp = f"{p}.tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, p)
    return p


def list_exams():
    if not os.path.isdir(_EXAM_DIR):
        return []
    out = []
    for fn in sorted(os.listdir(_EXAM_DIR)):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(_EXAM_DIR, fn)) as f:
                    d = json.load(f)
                out.append(d)
            except (OSError, ValueError):
                continue
    return out


# --------------------------------------------------------------------------- #
#  Scoring & time
# --------------------------------------------------------------------------- #
def earned_points(t):
    """Partial credit: root => full, foothold/local => half, else 0."""
    pts = int(t.get("points", DEFAULT_POINTS))
    st = t.get("status", "todo")
    if st == "root":
        return pts
    if st == "foothold":
        return pts // 2
    return 0


def score(data):
    earned = sum(earned_points(t) for t in data["targets"].values())
    possible = sum(int(t.get("points", DEFAULT_POINTS)) for t in data["targets"].values())
    return earned, possible


def exam_elapsed_secs(data):
    start = data.get("started_at") or data.get("created_at")
    if not start:
        return None
    return _secs_between(start, _now())


def target_time_secs(t):
    """Time from when the box was added to its furthest milestone reached
    (root/foothold/recon), or 'still running' if none reached yet."""
    added = t.get("added_at")
    for milestone in ("root_at", "foothold_at", "recon_done_at"):
        if t.get(milestone):
            return _secs_between(added, t[milestone]), False
    return _secs_between(added, _now()), True   # running


# --------------------------------------------------------------------------- #
#  Mutations
# --------------------------------------------------------------------------- #
def create_exam(name, budget=None, pass_mark=None, vault_note=None):
    data = {
        "name": name,
        "created_at": _now(),
        "started_at": None,
        "budget_secs": parse_duration(budget) if budget else DEFAULT_BUDGET_SECS,
        "pass_mark": int(pass_mark) if pass_mark else DEFAULT_PASS_MARK,
        "vault_note": vault_note,
        "targets": {},
    }
    save_exam(data)
    set_current(name)
    return data


def next_order(data):
    return 1 + max([t.get("order", 0) for t in data["targets"].values()] or [0])


def add_target(data, ip, points=None, label=None, os_type=None, set_name=None):
    t = data["targets"].get(ip)
    if t is None:
        order = next_order(data)
        t = {
            "ip": ip,
            "order": order,
            "label": label or f"Machine {order}",
            "points": int(points) if points is not None else DEFAULT_POINTS,
            "status": "todo",
            "os": os_type,
            "set": set_name,
            "added_at": _now(),
            "recon_done_at": None,
            "foothold_at": None,
            "root_at": None,
            "note": "",
            "ports": [],
            "top_findings": [],
        }
        data["targets"][ip] = t
    else:
        if points is not None:
            t["points"] = int(points)
        if label:
            t["label"] = label
        if os_type:
            t["os"] = os_type
        if set_name:
            t["set"] = set_name
    return t


def set_status(data, ip, status):
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    t = data["targets"].get(ip)
    if not t:
        t = add_target(data, ip)
    t["status"] = status
    stamp = {"recon": "recon_done_at", "foothold": "foothold_at", "root": "root_at"}.get(status)
    if stamp and not t.get(stamp):
        t[stamp] = _now()
    return t


def sync_from_scan(name, host, host_type=None, services=None, findings=None, ports=None):
    """Hook called by reconx after a scan finishes. Upserts the target,
    records OS/ports/top-findings, and advances it to at least 'recon'.
    Never downgrades a status you've already advanced past. Safe to call on
    a non-existent exam (silently no-ops)."""
    data = load_exam(name)
    if data is None:
        return None
    t = add_target(data, host, os_type=host_type)
    if host_type and not t.get("os"):
        t["os"] = host_type
    elif host_type:
        t["os"] = host_type
    if ports is not None:
        t["ports"] = sorted(set(ports))
    elif services:
        t["ports"] = sorted(int(p) for p in services)
    # store a compact, severity-ranked slice of findings
    if findings is not None:
        norm = []
        for f in findings:
            if hasattr(f, "sev"):
                norm.append([f.sev, f.service, f.port, f.text])
            elif isinstance(f, (list, tuple)) and len(f) >= 4:
                norm.append([f[0], f[1], f[2], f[3]])
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
        norm.sort(key=lambda x: rank.get(x[0], 9))
        t["top_findings"] = norm[:10]
    if _STATUS_RANK.get(t["status"], 0) < _STATUS_RANK["recon"]:
        set_status(data, host, "recon")
    else:
        t.setdefault("recon_done_at", None)
        if not t["recon_done_at"]:
            t["recon_done_at"] = _now()
    save_exam(data)
    return data


# --------------------------------------------------------------------------- #
#  Rendering
# --------------------------------------------------------------------------- #
def _sorted_targets(data):
    return sorted(data["targets"].values(), key=lambda t: t.get("order", 0))


def render_board(data, color=True):
    """The terminal dashboard. Returns a printable string."""
    C = _C if color else type("N", (), {k: "" for k in vars(_C) if not k.startswith("__")})
    earned, possible = score(data)
    pass_mark = data.get("pass_mark", DEFAULT_PASS_MARK)
    elapsed = exam_elapsed_secs(data)
    budget = data.get("budget_secs", DEFAULT_BUDGET_SECS)
    remaining = (budget - elapsed) if elapsed is not None else None

    started = bool(data.get("started_at"))
    clock = "running" if started else _C.DIM + "not started (exam start)" + _C.END
    pass_col = C.G if earned >= pass_mark else C.Y
    lines = []
    lines.append(f"{C.BOLD}{C.M}== OSCP EXAM: {data['name']} =={C.END}  {C.DIM}[{clock}]{C.END}")
    lines.append(
        f"  elapsed {C.CY}{fmt_hms(elapsed)}{C.END}"
        f"   budget-left {C.CY}{fmt_hms(remaining)}{C.END}"
        f"   score {pass_col}{earned}/{possible}{C.END}"
        f"  (pass {pass_mark}: {pass_col}{'PASS' if earned >= pass_mark else str(max(0, pass_mark-earned))+' pts to go'}{C.END})"
    )
    if not data["targets"]:
        lines.append(f"  {C.DIM}no targets yet - add one:  reconx exam add <ip> --points 20{C.END}")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"  {C.DIM}{'TARGET':<20}{'OS':<9}{'PTS':>4}  {'STATUS':<11}{'TIME':>9}{C.END}")
    for t in _sorted_targets(data):
        tsec, running = target_time_secs(t)
        emoji = STATUS_EMOJI.get(t["status"], "")
        scol = STATUS_COLOR.get(t["status"], "")
        label = f"{t['ip']}"
        osv = (t.get("os") or "?")[:8]
        run_mark = f"{C.DIM}~{C.END}" if running and t["status"] != "root" else " "
        lines.append(
            f"  {C.B}{label:<20}{C.END}{C.DIM}{osv:<9}{C.END}{int(t.get('points',0)):>4}  "
            f"{scol}{(t['status']):<10}{C.END}{emoji} {fmt_hms(tsec):>8}{run_mark}"
        )
    # sets rollup
    sets = {}
    for t in data["targets"].values():
        if t.get("set"):
            sets.setdefault(t["set"], []).append(t)
    if sets:
        lines.append("")
        for sname, members in sets.items():
            got = sum(earned_points(m) for m in members)
            pos = sum(int(m.get("points", 0)) for m in members)
            roots = sum(1 for m in members if m["status"] == "root")
            lines.append(f"  {C.M}set {sname}{C.END}: {roots}/{len(members)} rooted  {got}/{pos} pts")
    return "\n".join(lines)


def render_board_markdown(data):
    """Plain-markdown dashboard for embedding in the vault note."""
    earned, possible = score(data)
    elapsed = exam_elapsed_secs(data)
    remaining = (data.get("budget_secs", DEFAULT_BUDGET_SECS) - elapsed) if elapsed is not None else None
    pass_mark = data.get("pass_mark", DEFAULT_PASS_MARK)
    out = []
    out.append(f"**Exam:** {data['name']}  ")
    out.append(f"**Score:** {earned}/{possible} pts  (pass {pass_mark}: "
               f"{'PASS ✅' if earned >= pass_mark else str(max(0, pass_mark-earned)) + ' to go'})  ")
    out.append(f"**Elapsed:** {fmt_hms(elapsed)}  |  **Budget left:** {fmt_hms(remaining)}  ")
    out.append(f"_updated {datetime.now():%Y-%m-%d %H:%M}_\n")
    if data["targets"]:
        out.append("| # | Target | OS | Pts | Status | Time |")
        out.append("|---|--------|----|-----|--------|------|")
        for t in _sorted_targets(data):
            tsec, _ = target_time_secs(t)
            out.append(f"| {t.get('order','')} | `{t['ip']}` | {t.get('os') or '?'} | "
                       f"{t.get('points',0)} | {STATUS_EMOJI.get(t['status'],'')} {t['status']} | {fmt_hms(tsec)} |")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
#  CLI  (reconx exam <subcommand> ...)
# --------------------------------------------------------------------------- #
def _resolve(name):
    data = load_exam(name)
    if data is None:
        who = name or current_exam_name() or "(none)"
        _emsg(f"no exam '{who}'. Create one:  reconx exam init <name>")
        sys.exit(2)
    return data


def _maybe_rebuild_note(data):
    """Refresh the vault exam note if reconx_notes is importable and a note
    path is set. Best-effort; never fatal."""
    if not data.get("vault_note"):
        return
    try:
        import reconx_notes
    except ImportError:
        try:
            from . import reconx_notes  # if packaged
        except ImportError:
            return
    try:
        reconx_notes.build_exam_note(data)
    except Exception as e:  # noqa: BLE001 - note gen must never crash bookkeeping
        _emsg(f"vault note update skipped: {e}")


def exam_cli(argv):
    ap = argparse.ArgumentParser(
        prog="reconx exam",
        description="Multi-target OSCP exam manager, time budget & score dashboard.")
    sub = ap.add_subparsers(dest="cmd")

    def add_exam_flag(sp):
        sp.add_argument("--exam", help="exam name (default: current)")

    sp = sub.add_parser("init", help="create a new exam and make it current")
    sp.add_argument("name", help="exam name, e.g. OSCP-2026-09-10")
    sp.add_argument("--budget", help="hacking time budget (default 23h45m); e.g. 23h45m, 90m")
    sp.add_argument("--pass-mark", type=int, help="points needed to pass (default 70)")
    sp.add_argument("--vault-note", help="path to the Obsidian exam note to generate/refresh")

    sp = sub.add_parser("start", help="start (or restart) the exam clock now")
    add_exam_flag(sp)

    sp = sub.add_parser("add", help="register a target machine")
    add_exam_flag(sp)
    sp.add_argument("ip", help="target IP/hostname")
    sp.add_argument("--points", type=int, default=DEFAULT_POINTS)
    sp.add_argument("--label", help="display label (default: Machine N)")
    sp.add_argument("--os", dest="os_type", help="linux/windows/ad")
    sp.add_argument("--set", dest="set_name", help="group into a named set (e.g. AD)")

    sp = sub.add_parser("set", help="update a target's status/points/os/note")
    add_exam_flag(sp)
    sp.add_argument("ip")
    sp.add_argument("--status", choices=STATUSES)
    sp.add_argument("--points", type=int)
    sp.add_argument("--os", dest="os_type")
    sp.add_argument("--note")

    for alias in ("status", "board"):
        sp = sub.add_parser(alias, help="show the exam dashboard")
        add_exam_flag(sp)
        sp.add_argument("--no-color", action="store_true")

    sp = sub.add_parser("rm", help="remove a target")
    add_exam_flag(sp)
    sp.add_argument("ip")

    sub.add_parser("list", help="list all exams")

    sp = sub.add_parser("use", help="switch the current exam")
    sp.add_argument("name")

    sp = sub.add_parser("note", help="(re)generate the vault exam note")
    add_exam_flag(sp)
    sp.add_argument("--vault-note", help="set/override the note path")

    args = ap.parse_args(argv)

    if args.cmd == "init":
        if exam_exists(args.name):
            _emsg(f"exam '{args.name}' already exists; using it. (edit with 'exam set')")
            set_current(args.name)
            data = load_exam(args.name)
        else:
            data = create_exam(args.name, budget=args.budget,
                                pass_mark=args.pass_mark, vault_note=args.vault_note)
            _omsg(f"created exam '{args.name}'  budget {fmt_hms(data['budget_secs'])}  "
                  f"pass {data['pass_mark']}  (now current)")
        if args.vault_note:
            data["vault_note"] = os.path.expanduser(args.vault_note)
            save_exam(data)
            _maybe_rebuild_note(data)
        return 0

    if args.cmd == "start":
        data = _resolve(args.exam)
        data["started_at"] = _now()
        save_exam(data)
        _omsg(f"exam clock started at {data['started_at']}  "
              f"({fmt_hms(data['budget_secs'])} on the clock)")
        _maybe_rebuild_note(data)
        return 0

    if args.cmd == "add":
        data = _resolve(args.exam)
        t = add_target(data, args.ip, points=args.points, label=args.label,
                       os_type=args.os_type, set_name=args.set_name)
        save_exam(data)
        _omsg(f"+ {t['label']}  {args.ip}  {t['points']} pts"
              + (f"  [set {args.set_name}]" if args.set_name else ""))
        _maybe_rebuild_note(data)
        return 0

    if args.cmd == "set":
        data = _resolve(args.exam)
        if args.ip not in data["targets"]:
            _emsg(f"no target {args.ip} - adding it")
        t = data["targets"].get(args.ip) or add_target(data, args.ip)
        if args.status:
            set_status(data, args.ip, args.status)
        if args.points is not None:
            t["points"] = args.points
        if args.os_type:
            t["os"] = args.os_type
        if args.note is not None:
            t["note"] = args.note
        save_exam(data)
        _omsg(f"updated {args.ip}: status={t['status']} points={t['points']}")
        _maybe_rebuild_note(data)
        print()
        print(render_board(data))
        return 0

    if args.cmd in ("status", "board"):
        data = _resolve(args.exam)
        print(render_board(data, color=not getattr(args, "no_color", False)))
        return 0

    if args.cmd == "rm":
        data = _resolve(args.exam)
        if data["targets"].pop(args.ip, None):
            save_exam(data)
            _omsg(f"removed {args.ip}")
            _maybe_rebuild_note(data)
        else:
            _emsg(f"no target {args.ip}")
        return 0

    if args.cmd == "list":
        exams = list_exams()
        cur = current_exam_name()
        if not exams:
            print("no exams yet. Create one:  reconx exam init OSCP-YYYY-MM-DD")
            return 0
        for d in exams:
            earned, possible = score(d)
            mark = "*" if d["name"] == cur else " "
            print(f" {mark} {d['name']:<24} {len(d['targets'])} targets  "
                  f"{earned}/{possible} pts  budget {fmt_hms(d.get('budget_secs'))}")
        return 0

    if args.cmd == "use":
        if not exam_exists(args.name):
            _emsg(f"no exam '{args.name}'")
            return 2
        set_current(args.name)
        _omsg(f"current exam -> {args.name}")
        return 0

    if args.cmd == "note":
        data = _resolve(args.exam)
        if args.vault_note:
            data["vault_note"] = os.path.expanduser(args.vault_note)
            save_exam(data)
        if not data.get("vault_note"):
            _emsg("no --vault-note set for this exam")
            return 2
        _maybe_rebuild_note(data)
        _omsg(f"vault note refreshed: {data['vault_note']}")
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(exam_cli(sys.argv[1:]))
