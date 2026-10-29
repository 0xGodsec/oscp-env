#!/usr/bin/env python3
"""
reconx - a lean, fast, accurate reconnaissance orchestrator.

An AutoRecon alternative built for OSCP methodology: it discovers ports fast,
confirms them for accuracy, runs *targeted* per-service enumeration concurrently,
then prints a RANKED "what to look at first" summary instead of drowning you in
200 files. You still do the thinking; reconx does the parallel legwork.

Design goals
------------
  speed     : rustscan (if present) or a fast async connect-scan finds ports in
              seconds; heavy enumeration runs in the background while you work.
  accuracy  : two-pass port confirmation + nmap -sCV service/version detection so
              you don't chase phantom ports.
  lean      : curated commands per service, not "run everything on everything".
  yours     : stdlib only (Python 3.8+), single file, easy to read and hack
              mid-exam. Every external tool is optional with graceful fallback.

Ethics: authorized targets only (your lab, HTB/PG/THM, or written permission).

Usage
-----
  python3 reconx.py 10.10.10.10
  python3 reconx.py 10.10.10.0/24 --ping-sweep
  python3 reconx.py target.htb -o loot/ --top-ports 2000
  python3 reconx.py 10.10.10.10 --dry-run        # print the plan, run nothing
  python3 reconx.py 10.10.10.10 --no-udp --quick

Author: built with OffSec-OS (OSCP mentor). MIT-style, hack freely.
"""

import argparse
import asyncio
import functools
import glob
import ipaddress
import itertools
import json
import os
import re
import shlex
import shutil
import signal
import sys
import time
from datetime import datetime

# Optional companion modules (Obsidian/PakCyberbot notes + exam manager).
# reconx stays a working single file if these are absent - the features they
# add simply switch off.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import reconx_notes
except ImportError:
    reconx_notes = None
try:
    import reconx_exam
except ImportError:
    reconx_exam = None

# --------------------------------------------------------------------------- #
#  Terminal colours
# --------------------------------------------------------------------------- #
class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; CY = "\033[36m"; W = "\033[37m"; GR = "\033[90m"
    BOLD = "\033[1m"; DIM = "\033[2m"; END = "\033[0m"

    @classmethod
    def strip(cls):
        for k in list(vars(cls)):
            if not k.startswith("_") and isinstance(getattr(cls, k), str) and getattr(cls, k).startswith("\033"):
                setattr(cls, k, "")
        # module-level colour maps captured the old values at import time - reset them
        for d in (SEV_COLOR,):
            for key in d:
                d[key] = ""


def ts():
    return datetime.now().strftime("%H:%M:%S")


def info(msg):  print(f"{C.GR}[{ts()}]{C.END} {C.B}[*]{C.END} {msg}")
def good(msg):  print(f"{C.GR}[{ts()}]{C.END} {C.G}[+]{C.END} {msg}")
def warn(msg):  print(f"{C.GR}[{ts()}]{C.END} {C.Y}[!]{C.END} {msg}")
def bad(msg):   print(f"{C.GR}[{ts()}]{C.END} {C.R}[-]{C.END} {msg}")


# --------------------------------------------------------------------------- #
#  Severity model for the findings engine
# --------------------------------------------------------------------------- #
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
SEV_COLOR = {"CRITICAL": C.R + C.BOLD, "HIGH": C.R, "MEDIUM": C.Y, "INFO": C.CY}


class Finding:
    __slots__ = ("sev", "service", "port", "text")

    def __init__(self, sev, service, port, text):
        self.sev = sev
        self.service = service
        self.port = port
        self.text = text

    def __repr__(self):
        p = f":{self.port}" if self.port else ""
        return f"[{self.sev}] {self.service}{p} - {self.text}"


def _print_live_finding(f):
    col = SEV_COLOR.get(f.sev, "")
    p = f":{f.port}" if f.port else ""
    print(f"{C.GR}[{ts()}]{C.END} {col}[{f.sev}]{C.END} {C.DIM}{f.service}{p}{C.END}  {f.text}")


class FindingsList(list):
    """A list of Finding that prints each *new* one live as it's appended,
    instead of only ever surfacing findings in the final summary. De-duped
    on the same (sev, service, port, text) key print_summary/write_markdown
    already use, so re-registering the same job (guess pass + confirm pass)
    or a rerun rule never double-prints. Optionally persists new findings to
    a StateStore so a job that's skipped on --resume (because it already
    completed in an earlier, interrupted run) doesn't silently vanish from
    NOTES.md - findings, unlike command output, only ever live in memory
    otherwise."""

    def __init__(self, *a, state_store=None, dry_run=False, **kw):
        super().__init__(*a, **kw)
        self._seen = set()
        self._state_store = state_store
        self._dry_run = dry_run

    def append(self, finding):
        # --dry-run runs no commands, so every module sees the rc=0/empty stub
        # from Runner.run - which makes rc-gated checks (e.g. enum_ftp's
        # "curl exited 0 => anonymous login") falsely fire. The command plan is
        # the only intended dry-run output, so suppress finding emission entirely
        # rather than print proof-less findings.
        if self._dry_run:
            return
        key = (finding.sev, finding.service, finding.port, finding.text)
        if key in self._seen:
            return
        super().append(finding)
        self._seen.add(key)
        _print_live_finding(finding)
        if self._state_store:
            self._state_store.record_finding(finding)

    def seed(self, finding):
        """Add a finding restored from persisted state, without a live
        reprint or re-recording it - it's already in the state file."""
        key = (finding.sev, finding.service, finding.port, finding.text)
        if key not in self._seen:
            super().append(finding)
            self._seen.add(key)


# --------------------------------------------------------------------------- #
#  Tool availability (graceful degradation)
# --------------------------------------------------------------------------- #
def which(name):
    return shutil.which(name) is not None


TOOLS = {}
def refresh_tools():
    for t in ("rustscan", "nmap",
              "curl", "enum4linux-ng", "enum4linux", "nxc", "netexec", "crackmapexec",
              "smbclient", "rpcclient", "ldapsearch",
              "snmpwalk", "onesixtyone", "showmount", "dig",
              "redis-cli", "psql", "mysql", "mariadb", "openssl", "ncat", "nc",
              "searchsploit",
              "whatweb", "feroxbuster", "gobuster", "ffuf", "nikto",
              "impacket-GetUserSPNs", "GetUserSPNs.py",
              "impacket-GetNPUsers", "GetNPUsers.py",
              "bloodhound-python", "bloodhound-ce-python",
              "smtp-user-enum"):
        TOOLS[t] = which(t)


def _first_tool(*candidates):
    """Return the first candidate binary name found installed, or None."""
    for cand in candidates:
        if TOOLS.get(cand):
            return cand
    return None


# Capability groups for the startup "tools available / missing" summary. Each
# capability is satisfied by ANY one of its candidate binaries (aliases): e.g.
# netexec counts as present if nxc OR netexec OR crackmapexec is installed, and
# the web dir-brute capability if feroxbuster OR gobuster OR ffuf is. Derived
# from the full TOOLS table (not a hardcoded subset) so the summary can't
# silently hide a missing capability - the headline "flags missing tools"
# guarantee only holds if every capability a module relies on is reported.
CAPABILITY_GROUPS = [
    ("rustscan",         ["rustscan"]),
    ("nmap",             ["nmap"]),
    ("netexec",          ["nxc", "netexec", "crackmapexec"]),
    ("smbclient",        ["smbclient"]),
    ("rpcclient",        ["rpcclient"]),
    ("enum4linux",       ["enum4linux-ng", "enum4linux"]),
    ("ldapsearch",       ["ldapsearch"]),
    ("GetUserSPNs",      ["impacket-GetUserSPNs", "GetUserSPNs.py"]),
    ("GetNPUsers",       ["impacket-GetNPUsers", "GetNPUsers.py"]),
    ("bloodhound-python", ["bloodhound-python", "bloodhound-ce-python"]),
    ("snmpwalk",         ["snmpwalk"]),
    ("onesixtyone",      ["onesixtyone"]),
    ("showmount",        ["showmount"]),
    ("dig",              ["dig"]),
    ("smtp-user-enum",   ["smtp-user-enum"]),
    ("redis-cli",        ["redis-cli"]),
    ("psql",             ["psql"]),
    ("mysql",            ["mysql", "mariadb"]),
    ("searchsploit",     ["searchsploit"]),
    ("whatweb",          ["whatweb"]),
    ("dir-brute",        ["feroxbuster", "gobuster", "ffuf"]),
    ("nikto",            ["nikto"]),
    ("curl",             ["curl"]),
    ("openssl",          ["openssl"]),
    ("nc",               ["ncat", "nc"]),
]


def tool_availability():
    """(present, missing) capability-label lists for the startup summary, built
    from the full TOOLS table. A capability is present if ANY alias binary is
    installed (its found name is shown); missing if none are. Replaces the old
    hardcoded subset lists that reported ~10 tools and hid the rest, so a box
    missing e.g. ldapsearch / searchsploit / the dir-brute tools now says so."""
    present, missing = [], []
    for label, candidates in CAPABILITY_GROUPS:
        found = next((c for c in candidates if TOOLS.get(c)), None)
        (present.append(found) if found else missing.append(label))
    return present, missing


def _first_existing_file(candidates):
    """Return the first candidate path that exists on disk, or None."""
    for cand in candidates:
        if os.path.isfile(cand):
            return cand
    return None


# --------------------------------------------------------------------------- #
#  Command runner
# --------------------------------------------------------------------------- #
class Runner:
    def __init__(self, outdir, dry_run=False, timeout=900, verbose=False, resume=False):
        self.outdir = outdir
        self.dry_run = dry_run
        self.timeout = timeout
        self.verbose = verbose
        self.resume = resume
        self.plan = []          # for --dry-run
        self.sem = None         # set once loop exists
        # flat=True drops the per-host directory level from every output path -
        # used in --workspace mode (exactly one host per run), so results land
        # directly under <workspace>/scans/reconx/ instead of a redundant
        # <workspace>/scans/reconx/<host>/ level. See hostdir() and amain().
        self.flat = False

    def hostdir(self, host):
        """The per-host output base. Flat mode collapses it to outdir itself."""
        return self.outdir if self.flat else os.path.join(self.outdir, host)

    async def run(self, cmd, outfile=None, label=None, timeout=None):
        """Run a shell command, tee output to a file, return (rc, stdout+stderr)."""
        label = label or cmd.split()[0]
        # Callers pass outfile as "<host>/<service>/..."; in flat mode strip that
        # leading host segment so it maps under outdir directly (single host only).
        if self.flat and outfile and "/" in outfile:
            outfile = outfile.split("/", 1)[1]
        if self.dry_run:
            self.plan.append((label, cmd, outfile))
            return 0, ""
        if self.resume and outfile:
            path = os.path.join(self.outdir, outfile)
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                stale = False
                with open(path, errors="replace") as f:
                    cached = f.read()
                # strip the "# cmd: ...\n\n" header we write below, if present,
                # and use it to detect a changed command (e.g. --mode changed
                # since the cached file was written) rather than blindly
                # trusting whatever's on disk at this path.
                if cached.startswith("# cmd:") and "\n\n" in cached:
                    header, rest = cached.split("\n\n", 1)
                    if header[len("# cmd: "):] != cmd:
                        stale = True
                    cached = rest
                if not stale:
                    if self.verbose:
                        info(f"resume: {C.DIM}skipping {label}, using cached {path}{C.END}")
                    return 0, cached
                if self.verbose:
                    info(f"resume: {C.DIM}cached {path} is from a different command, re-running {label}{C.END}")
        async with self.sem:
            if self.verbose:
                info(f"run: {C.DIM}{cmd}{C.END}")
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    preexec_fn=os.setsid,
                )
                try:
                    out, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=timeout or self.timeout)
                except asyncio.TimeoutError:
                    # cmd runs via a shell, so proc.kill() would only kill the
                    # shell - tools that fork workers (enum4linux-ng, nmap NSE, ...) keep
                    # running. Kill the whole process group instead.
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    warn(f"timeout ({label}) after {timeout or self.timeout}s")
                    return 124, ""
                text = out.decode(errors="replace") if out else ""
                if outfile:
                    path = os.path.join(self.outdir, outfile)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", errors="replace") as f:
                        f.write(f"# cmd: {cmd}\n\n{text}")
                return proc.returncode, text
            except FileNotFoundError:
                bad(f"command not found: {cmd.split()[0]}")
                return 127, ""


# --------------------------------------------------------------------------- #
#  Priority job queue - the scan engine
#
#  Every job is only ever registered by code that runs *after* awaiting its
#  own prerequisite (e.g. a service-enum job is added from inside the
#  coroutine that just discovered the port), so a job is always runnable the
#  instant it's added - there's no separate dependency graph to resolve.
#  Concurrency and "only run what's relevant" come from WHEN jobs get added
#  and a bounded worker pool draining a priority queue, not from every module
#  being force-started together behind one phase barrier.
# --------------------------------------------------------------------------- #
PRIO_DISCOVER, PRIO_SCAN = 0, 1
# 3-way split of the old flat PRIO_ENUM=2, so host-type-aware scheduling
# (see classify_host_type/_service_priority) can weight one enum module
# ahead of another without touching PRIO_EXPLOIT/PRIO_BACKGROUND's relative
# order - only relative order matters anywhere these are used, so this
# renumbering is safe.
PRIO_ENUM_HIGH, PRIO_ENUM, PRIO_ENUM_LOW = 2, 3, 4
PRIO_EXPLOIT, PRIO_BACKGROUND = 5, 6


class Job:
    __slots__ = ("id", "priority", "background", "coro_factory", "status", "always_reenter")

    def __init__(self, id, priority, coro_factory, background=False, always_reenter=False):
        self.id = id
        self.priority = priority
        self.coro_factory = coro_factory
        self.background = background
        self.status = "queued"
        # True for orchestrator jobs (discover/service_scan) whose coroutine
        # body has a side effect - registering follow-up jobs - beyond just
        # "did the work", so it must always be entered even when the state
        # store says "done". Their own bodies still skip the real work and
        # reuse cached ports/services; leaf enum_* jobs don't need this and
        # get the full skip-without-reentering benefit on resume.
        self.always_reenter = always_reenter


class StateStore:
    """Persists <outdir>/<host>/.reconx_state.json so an interrupted scan can
    resume without re-orchestrating every module from scratch. Only "done"/
    "failed" job statuses are ever written - a job mid-flight at crash time
    simply has no entry, so "absent -> not done -> re-run" falls out for free
    without a separate stale "running" state to worry about."""

    def __init__(self, outdir, host, flat=False):
        base = outdir if flat else os.path.join(outdir, host)
        self.path = os.path.join(base, ".reconx_state.json")
        self.data = {"target": host, "mode": None, "started_at": None,
                     "ports": [], "services": {}, "udp": {}, "jobs": {}, "findings": []}
        self._lock = asyncio.Lock()

    def load(self):
        if os.path.isfile(self.path):
            try:
                with open(self.path) as f:
                    on_disk = json.load(f)
                on_disk["services"] = {int(k): v for k, v in on_disk.get("services", {}).items()}
                self.data.update(on_disk)
            except (ValueError, OSError, TypeError) as e:
                warn(f"state file unreadable, ignoring ({e}): {self.path}")
        return self.data

    def job_status(self, job_id):
        return self.data.get("jobs", {}).get(job_id, {}).get("status")

    async def mark_job(self, job_id, status):
        async with self._lock:
            self.data["jobs"][job_id] = {
                "status": status,
                "finished_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._flush()

    def record_finding(self, finding):
        """Synchronous and lock-free by design: called from FindingsList.append(),
        which - like add_job() - never awaits, so it can't be interleaved with
        another coroutine on this single-threaded event loop."""
        entry = [finding.sev, finding.service, finding.port, finding.text]
        findings = self.data.setdefault("findings", [])
        if entry not in findings:
            findings.append(entry)
            self._flush()

    async def save_ports_services(self, ports=None, services=None, udp=None):
        async with self._lock:
            if ports is not None:
                self.data["ports"] = ports
            if services is not None:
                self.data["services"] = services
            if udp is not None:
                self.data["udp"] = udp
            self._flush()

    def _flush(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = f"{self.path}.tmp.{os.getpid()}"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        os.replace(tmp, self.path)  # atomic - no torn JSON on crash


class JobQueue:
    """Priority-ordered, bounded-worker-pool job runner.

    add_job() is synchronous (no `await` inside) so the dedup check-then-
    insert is atomic under cooperative scheduling - two coroutines racing to
    register the same job id can never both win. A job already marked "done"
    in a resumed StateStore is accepted into .jobs (for bookkeeping/back-refs)
    but never queued for execution - its coroutine is never entered at all.

    "Core" jobs (background=False) gate wait_core_done(); background jobs
    (udp/vuln-scan) run alongside everything else without
    blocking it. wait_all_done() waits for every job, core or background.
    """

    def __init__(self, workers=8, state_store=None):
        self._q = asyncio.PriorityQueue()
        self._seq = itertools.count()  # heapq tie-break: Job isn't orderable
        self.jobs = {}
        self.state_store = state_store
        self._core_inflight = 0
        self._core_done = asyncio.Event()
        self._core_done.set()
        self._nworkers = workers
        self._workers = []
        self.had_background_jobs = False

    async def __aenter__(self):
        self._workers = [asyncio.create_task(self._worker()) for _ in range(self._nworkers)]
        return self

    async def __aexit__(self, *exc):
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)

    def add_job(self, job):
        """Register a job, or - if this id is already known and still
        queued (not yet picked up by a worker) - reprioritize it: decrease-
        key via a duplicate heap entry. heapq always pops the numerically
        smallest priority first regardless of insertion order, so whichever
        entry currently matches job.priority (the single source of truth)
        wins the race; _worker() discards any other, now-stale entry for
        the same job on pop. This is what lets register_service_jobs()'s
        confirm pass (better host-type info from nmap -sCV) correct a
        still-queued job's priority from the earlier guess pass, with zero
        change needed at either call site.

        Also always refreshes coro_factory to the newest registration's
        closure while still queued - the whole point of the confirm pass is
        that it carries more accurate arguments (e.g. the real nmap-
        confirmed service name instead of a port-guessed one), and a worker
        reads job.coro_factory live at execution time, so this is enough to
        make sure a reprioritized job actually runs with fresh data instead
        of silently executing with the stale guess-pass closure."""
        existing = self.jobs.get(job.id)
        if existing is not None:
            if existing.status == "queued":
                existing.coro_factory = job.coro_factory
                if existing.priority != job.priority:
                    existing.priority = job.priority
                    self._q.put_nowait((job.priority, next(self._seq), existing))
            return False
        self.jobs[job.id] = job
        if (self.state_store and not job.always_reenter
                and self.state_store.job_status(job.id) == "done"):
            job.status = "done"  # resumed: trust it, never enter the coroutine
            return False
        if job.background:
            self.had_background_jobs = True
        else:
            self._core_inflight += 1
            self._core_done.clear()
        self._q.put_nowait((job.priority, next(self._seq), job))
        return True

    async def _worker(self):
        while True:
            priority, _, job = await self._q.get()
            if job.status != "queued" or priority != job.priority:
                # stale duplicate entry from a reprioritization, or the job
                # already started/finished via its other entry - discard.
                self._q.task_done()
                continue
            job.status = "running"
            try:
                await job.coro_factory()
                job.status = "done"
            except asyncio.CancelledError:
                raise
            except Exception as e:
                job.status = "failed"
                bad(f"job '{job.id}' failed: {e}")
            finally:
                if self.state_store and job.status in ("done", "failed"):
                    await self.state_store.mark_job(job.id, job.status)
                if not job.background:
                    self._core_inflight -= 1
                    if self._core_inflight <= 0:
                        self._core_done.set()
                self._q.task_done()

    async def wait_core_done(self):
        await self._core_done.wait()

    async def wait_all_done(self):
        await self._q.join()


# --------------------------------------------------------------------------- #
#  Port discovery
# --------------------------------------------------------------------------- #
async def tcp_connect(host, port, timeout=1.5):
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None


async def async_port_scan(host, ports, concurrency=800, timeout=1.5):
    """Pure-Python fallback scanner. Fast async TCP connect sweep."""
    sem = asyncio.Semaphore(concurrency)
    found = []

    async def probe(p):
        async with sem:
            r = await tcp_connect(host, p, timeout)
            if r:
                found.append(r)

    await asyncio.gather(*(probe(p) for p in ports))
    return sorted(found)


# Fallback concurrency for the zero-ports retry in discover_ports(). Chosen
# empirically against scanme.nmap.org across two independent trials (a
# 50-port subset and the full 1000-port TOP_1000 list): concurrency=50
# dropped every connection on the full list (false "no open ports") even
# though it had worked on the smaller subset, while concurrency=20 found the
# true open ports reliably in every trial. 20 is the highest value borne out
# by testing, not just a round number below the failure point.
RETRY_SCAN_CONCURRENCY = 20


async def discover_ports(host, runner, args):
    """Return a sorted list of open TCP ports.

    A fast connect-based sweep (rustscan, else the built-in async scanner)
    finds ports in seconds, but both discover ports by firing large bursts of
    TCP connections - and a rate-limiting host or firewall can silently drop a
    burst. That produces either an EMPTY result or, more insidiously, a PARTIAL
    one that looks like a genuine finding (confirmed against scanme.nmap.org:
    rustscan variously returned [], [9929,31337], and [31337] across runs while
    22/80/9929/31337 were all open). nmap's adaptive timing + retransmission
    survive that throttling, so it's the accuracy authority the README promises,
    and we ALWAYS run it as a confirmation/union pass when nmap is present:

      * bounded scopes (--quick / --top-ports): an nmap confirmation pass costs
        only seconds, so always run it and UNION in whatever the fast sweep
        missed. This closes both the empty and the partial-result holes.
      * full range (-p-): nmap -p- costs a couple of minutes on a live host, but
        a silently under-reported port list costs hours of a stuck engagement
        (an AD host throttling the fast sweep down to 3 of its dozen-plus open
        ports is the exact failure this guards against). So we run nmap -p- here
        too and UNION its results in - accuracy wins over the saved minutes. On a
        genuinely-down host the fast sweep finds nothing and nmap -p- -Pn is the
        same last-resort pass it always was.
    """
    # Full range unless --quick/--top-ports narrows it.
    if args.quick:
        port_list = TOP_1000
        bounded = True
    elif args.top_ports:
        port_list = TOP_1000[: args.top_ports] if args.top_ports <= len(TOP_1000) else range(1, 65536)
        bounded = True
    else:
        port_list = range(1, 65536)
        bounded = False

    ports = set()

    if TOOLS.get("rustscan") and not args.no_rustscan:
        info(f"port discovery via rustscan ({'top 1000' if args.quick else 'full range'})")
        rng = "--top" if args.quick else "-r 1-65535"
        # Gentler batch/ulimit than rustscan's defaults: a 1500-connection burst
        # readily trips rate-limiting on hardened hosts (notably AD servers),
        # making rustscan silently under-report. -b 500 keeps far fewer sockets
        # in flight at once, so the sweep is less likely to be throttled into a
        # partial result in the first place; the nmap confirmation pass in
        # discover_ports() remains the accuracy backstop either way.
        cmd = (f"rustscan -a {host} {rng} --ulimit 5000 -b 500 "
               f"-t {int(args.host_timeout*1000)} -g")
        rc, out = await runner.run(cmd, outfile=f"{host}/scans/rustscan.txt",
                                   label="rustscan", timeout=args.scan_timeout)
        ports.update(parse_rustscan_greppable(out))
        if not ports:
            warn("rustscan returned nothing; falling back to async scanner")

    # Async connect-sweep: the primary when rustscan is absent, the fallback
    # when it came up empty. (When rustscan already found ports we skip straight
    # to the nmap confirmation below rather than double-sweeping.)
    if not ports and not runner.dry_run:
        info(f"port discovery via async connect-scan ({'top 1000' if bounded else 'full 65535'})")
        found = await async_port_scan(host, list(port_list),
                                      concurrency=args.concurrency,
                                      timeout=args.host_timeout)
        if not found and args.concurrency > RETRY_SCAN_CONCURRENCY:
            # A burst of hundreds of simultaneous connection attempts can trip a
            # host's or firewall's rate-limiting and silently drop every probe -
            # confirmed directly: scanme.nmap.org dropped 100% of connections at
            # concurrency=100 despite having open ports, but succeeded reliably
            # at 20. Re-probe at a much lower concurrency to distinguish "truly
            # no open ports" from "got rate-limited" - but BOUND the probe to a
            # TOP_1000 confirmation subset. A full -p- retry at concurrency 20
            # is ~65535/20 x host_timeout, i.e. ~80 min on a genuinely-down host
            # (exactly when this path fires), so only commit to a full-range
            # low-concurrency sweep once the cheap subset proves throttling is
            # real. If the subset stays empty, fall through to the nmap fallback
            # below (nmap's retransmission is the accuracy authority anyway) so
            # a dead host costs seconds here, not tens of minutes.
            confirm_ports = list(port_list) if bounded else TOP_1000
            warn(f"0 ports found at concurrency={args.concurrency} - re-probing "
                 f"{len(confirm_ports)} common ports at concurrency="
                 f"{RETRY_SCAN_CONCURRENCY} in case of rate-limiting")
            found = await async_port_scan(host, confirm_ports,
                                          concurrency=RETRY_SCAN_CONCURRENCY,
                                          timeout=args.host_timeout)
            if found and not bounded:
                # Throttling confirmed on the subset: a full-range sweep at low
                # concurrency is now worth its cost (real open ports are being
                # dropped by the burst, not simply absent).
                warn(f"rate-limiting confirmed ({len(found)} port(s) on the "
                     f"subset) - full-range sweep at concurrency="
                     f"{RETRY_SCAN_CONCURRENCY}")
                found = await async_port_scan(host, list(port_list),
                                              concurrency=RETRY_SCAN_CONCURRENCY,
                                              timeout=args.host_timeout)
        ports.update(found)

    # nmap: ALWAYS confirm the fast result (bounded or full -p-) when nmap is
    # available, and UNION in anything it found. The fast sweep fires large
    # connection bursts that a rate-limiting host/firewall silently drops,
    # yielding a PARTIAL result that looks genuine - e.g. an AD host reporting
    # only 3 of its dozen-plus open ports. nmap's retransmission survives that
    # throttling, so skipping it on full-range scans was under-reporting ports.
    # See the docstring for the accuracy-over-minutes trade-off.
    if TOOLS.get("nmap"):
        before = set(ports)
        ports.update(await nmap_discover(host, runner, args, confirm=bool(before)))
        gained = ports - before
        if before and gained:
            warn(f"nmap confirmation found {len(gained)} port(s) the fast sweep "
                 f"missed (likely rate-limited): {', '.join(map(str, sorted(gained)))}")

    return sorted(ports)


async def nmap_discover(host, runner, args, confirm=False):
    """Port discovery via nmap, used by discover_ports either to confirm a fast
    sweep on a bounded scope or as the last resort when the fast sweep found
    nothing. Mirrors the scan scope chosen there. Scan type is left to nmap: a
    privileged run gets the faster SYN scan, an unprivileged one falls back to
    TCP connect - both keep nmap's retransmission, which is what survives
    connection-burst throttling.
    """
    if args.quick:
        pspec = "--top-ports 1000"
    elif args.top_ports:
        pspec = f"--top-ports {args.top_ports}"
    else:
        pspec = "-p-"
    cmd = f"nmap -Pn --open {pspec} -oN /dev/stdout {host}"
    info(f"port discovery via nmap ({pspec}) - "
         f"{'confirming fast sweep' if confirm else 'fallback after empty connect-scan'}")
    rc, out = await runner.run(cmd, outfile=f"{host}/scans/nmap_discovery.txt",
                               label="nmap-discovery", timeout=args.scan_timeout)
    return sorted(parse_nmap_ports(out).keys())


def parse_rustscan_greppable(text):
    """rustscan -g prints:  host -> [22,80,443]"""
    ports = set()
    for m in re.finditer(r"->\s*\[([0-9,\s]+)\]", text):
        for p in m.group(1).split(","):
            p = p.strip()
            if p.isdigit():
                ports.add(int(p))
    # also catch 'Open 10.0.0.1:22' style lines
    for m in re.finditer(r"Open\s+[\d.]+:(\d+)", text):
        ports.add(int(m.group(1)))
    return sorted(ports)


def parse_nmap_ports(text):
    """Parse open ports + service guesses from nmap normal output."""
    services = {}
    for line in text.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line)
        if m:
            port = int(m.group(1))
            svc = m.group(2)
            ver = m.group(3).strip()
            services[port] = {"name": svc, "version": ver}
    return services


# --------------------------------------------------------------------------- #
#  Accuracy pass: nmap -sCV service/version detection on confirmed ports
# --------------------------------------------------------------------------- #
async def service_scan(host, ports, runner, args):
    if not ports:
        return {}
    if not TOOLS.get("nmap"):
        warn("nmap not found - skipping service/version detection (accuracy reduced)")
        # best-effort banner grab so we still have *something*
        return await banner_fallback(host, ports)

    plist = ",".join(str(p) for p in ports)
    scripts = "" if args.no_scripts else "-sC"
    intensity = getattr(args, "version_intensity", None)
    intensity = 6 if intensity is None else intensity
    cmd = (f"nmap -Pn -sV {scripts} -p {plist} --version-intensity {intensity} "
           f"-oN /dev/stdout {host}")
    info(f"service/version detection on {len(ports)} port(s) via nmap -sCV")
    rc, out = await runner.run(cmd, outfile=f"{host}/scans/nmap_service.txt",
                               label="nmap-sCV", timeout=args.scan_timeout)
    if runner.dry_run:
        return {p: {"name": "?", "version": ""} for p in ports}
    services = parse_nmap_ports(out)
    # ensure every discovered port is represented even if nmap was terse
    for p in ports:
        services.setdefault(p, {"name": guess_service(p), "version": ""})
    return services


async def banner_fallback(host, ports):
    services = {}
    for p in ports:
        services[p] = {"name": guess_service(p), "version": ""}
    return services


# --------------------------------------------------------------------------- #
#  Exploit-DB lookups for detected service versions
# --------------------------------------------------------------------------- #
# words too generic/decorative to be trustworthy exploit-db search terms on
# their own (org acronyms, protocol/transport words, banner filler) - a bare
# hit on one of these is noise, not a real correlation (e.g. 'ISC 9.4.2' from
# 'ISC BIND 9.4.2' matches unrelated Cisco/Avast CVEs by version-range fluke).
_SEARCHSPLOIT_TOO_GENERIC = {
    "isc", "db", "ip", "ns", "gnu", "www", "ftp", "ssh", "http", "https",
    "dns", "tcp", "udp", "smb", "sql", "protocol", "engine", "jsp", "org", "v1",
}


def _searchsploit_terms(version):
    """Build candidate searchsploit query terms from an nmap version string,
    most specific first, e.g. 'Samba smbd 3.0.20-Debian' -> ['Samba smbd
    3.0.20', 'Samba 3.0.20']. nmap's product name doesn't always match
    exploit-db's naming (extra words like 'httpd'/'smbd' break AND-matching),
    so a clean two-word 'vendor product' name also gets tried word-by-word.
    Longer name phrases are left as just the full-phrase attempt: when nmap's
    version field puts several words between the product name and the number
    (e.g. 'Apache Tomcat/Coyote JSP engine 1.1', where 1.1 is the JSP spec
    version, not Apache's), that number likely doesn't belong to the first
    word at all, so guessing single-word fallbacks there does more harm
    (wrong product) than good."""
    m = re.match(r"^(.*?)\s+((?:\d+\.){1,3}\d+[A-Za-z0-9]*)", version or "")
    if not m:
        return []
    name_part, ver = m.group(1).strip(), m.group(2)
    words = name_part.split()
    terms = [f"{name_part} {ver}"]
    if len(words) == 2:
        for w in (words[0], words[-1]):
            w = re.sub(r"[^A-Za-z0-9]", "", w)
            if w and w.lower() not in _SEARCHSPLOIT_TOO_GENERIC:
                terms.append(f"{w} {ver}")
    return terms


async def searchsploit_lookup(host, services, runner, args, findings):
    """Best-effort exploit-db correlation for each detected service version.
    Opportunistic: a version banner that doesn't cleanly map to exploit-db's
    naming just yields no results rather than a false positive."""
    if args.no_exploit_search or not TOOLS.get("searchsploit"):
        return

    async def check(port, meta):
        for term in _searchsploit_terms(meta.get("version", "")):
            rc, out = await runner.run(f"searchsploit -j {shlex.quote(term)}",
                                       None, "searchsploit", timeout=20)
            if runner.dry_run or not out:
                continue
            try:
                data = json.loads(out)
            except ValueError:
                continue
            hits = data.get("RESULTS_EXPLOIT") or []
            if hits:
                titles = "; ".join(h.get("Title", "?") for h in hits[:3])
                more = f" (+{len(hits) - 3} more)" if len(hits) > 3 else ""
                findings.append(Finding("MEDIUM", "exploit", port,
                    f"searchsploit hit for '{term}': {titles}{more} - verify before use"))
                return  # most-specific successful term wins; don't re-search broader terms

    # return_exceptions=True: this is a best-effort correlation pass, so one
    # port's check() raising shouldn't leave the other ports' checks running
    # as orphaned tasks JobQueue never awaits/cleans up.
    results = await asyncio.gather(*(check(p, m) for p, m in services.items()),
                                   return_exceptions=True)
    for r in results:
        if isinstance(r, BaseException):
            warn(f"{host}: searchsploit correlation failed for a service - {r}")


async def udp_scan(host, runner, args):
    if args.no_udp or not TOOLS.get("nmap"):
        return {}
    info("top-100 UDP scan via nmap (background; slow by nature)")
    cmd = f"nmap -Pn -sU --top-ports 100 --open -oN /dev/stdout {host}"
    rc, out = await runner.run(cmd, outfile=f"{host}/scans/nmap_udp.txt",
                               label="nmap-udp", timeout=args.scan_timeout)
    if runner.dry_run:
        return {}
    return parse_nmap_udp(out)


def parse_nmap_udp(text):
    """Parse open UDP ports from nmap -sU normal output. UDP ports frequently
    report 'open|filtered' (no response = can't distinguish open from filtered),
    which includes real SNMP/TFTP/etc. The earlier `\\s+open\\s+` match dropped
    every such line; capture both states and label the uncertain one so it's not
    mistaken for a confirmed-open port."""
    udp = {}
    for line in (text or "").splitlines():
        m = re.match(r"^(\d+)/udp\s+(open\|filtered|open)\s+(\S+)", line)
        if m:
            name = m.group(3)
            udp[int(m.group(1))] = name if m.group(2) == "open" else f"{name} (open|filtered)"
    return udp


# --------------------------------------------------------------------------- #
#  Service classification
# --------------------------------------------------------------------------- #
COMMON = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "ms-sql", 1521: "oracle", 2049: "nfs", 3128: "http-proxy",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5985: "winrm",
    5986: "winrm-ssl", 6379: "redis", 8080: "http-proxy", 8000: "http-alt",
    8443: "https-alt", 88: "kerberos-sec", 27017: "mongodb", 9200: "elasticsearch",
}

def guess_service(port):
    return COMMON.get(port, "unknown")


WEB_PORTS = {80, 443, 8080, 8000, 8443, 8888, 3128, 9200, 5000, 8081}
def is_web(port, name):
    return port in WEB_PORTS or "http" in name.lower() or name.lower() in ("ssl/http", "http-alt")


_AD_PORTS = {88, 389, 636, 3268, 3269, 464, 9389}
_LINUX_PORTS = {22, 111, 2049}

HOST_TYPE_LABELS = {
    "ad": "Active Directory host",
    "windows": "Windows host",
    "linux": "Linux host",
    "web": "web-focused host",
}


def classify_host_type(ports, services):
    """Soft, single dominant archetype from open ports + (guessed or
    confirmed) service names - drives enum priority weighting only, never
    a hard branch: an 'ad'-classified host still gets its web ports
    enumerated, just later. No extra scan needed - runs on whatever
    discover_ports()/service_scan() already produced.

    445/139 alone can't tell real Windows apart from Samba-on-Linux (any
    Linux fileserver, most CTF/Metasploitable-style boxes) - confirmed
    banner text is checked first and wins whenever it's available (i.e.
    once nmap -sCV has run), with a bare-port fallback for the earlier
    guess pass that only trusts genuinely Windows-exclusive ports."""
    ports = set(ports)
    names_blob = " ".join(
        f"{(services.get(p, {}).get('name','') or '')} {(services.get(p, {}).get('version','') or '')}"
        for p in ports).lower()

    ad_hits = len(ports & _AD_PORTS)
    if ad_hits >= 2 or (ad_hits >= 1 and (445 in ports or 139 in ports)):
        return "ad"
    if "samba" in names_blob:
        return "linux"
    if "windows" in names_blob:
        return "windows"
    if ports & {3389, 5985, 5986}:      # RDP/WinRM - essentially Windows-exclusive
        return "windows"
    if ports & _LINUX_PORTS:            # ssh/rpcbind/nfs - strong pre-banner Linux signal
        return "linux"
    if ports & {135, 139, 445}:         # SMB-only, no banner yet, no other signal - lean windows
        return "windows"
    web_ports = sum(1 for p in ports if is_web(p, (services.get(p, {}).get("name", "") or "")))
    if web_ports and (len(ports) - web_ports) <= 1:
        return "web"
    return "unknown"


# --------------------------------------------------------------------------- #
#  Credentials - authenticated enumeration & spraying
# --------------------------------------------------------------------------- #
def have_creds(args):
    return bool(getattr(args, "user", None) and (getattr(args, "password", None) is not None
                                                 or getattr(args, "hash", None)))


def nxc_auth(args):
    """Build the netexec/crackmapexec credential argument string from parsed args."""
    parts = [f"-u {shlex.quote(args.user)}"]
    if getattr(args, "hash", None):
        parts.append(f"-H {shlex.quote(args.hash)}")
    else:
        parts.append(f"-p {shlex.quote(args.password)}")
    if getattr(args, "domain", None):
        parts.append(f"-d {shlex.quote(args.domain)}")
    if getattr(args, "local_auth", False):
        parts.append("--local-auth")
    return " ".join(parts)


def nxc_bin():
    return _first_tool("nxc", "netexec", "crackmapexec")


def _nxc_login_ok(out):
    """True if netexec/crackmapexec output confirms a working login."""
    return bool(out) and ("[+]" in out or "Pwn3d" in out)


async def _nxc_authed_check(nxc, service, host, port, runner, findings, args,
                             outfile, label, extra="", auth=None,
                             success=None, on_fail=None):
    """Run a single authenticated netexec check, log it as a finding via
    scan_findings, and append `success`/`on_fail` Finding(s) depending on
    whether the login was confirmed. Returns True if the login worked."""
    auth = nxc_auth(args) if auth is None else auth
    cmd = f"{nxc} {service} {host} {auth} {extra}".strip()
    rc, out = await runner.run(cmd, outfile, label)
    scan_findings(out, service, port, findings)
    ok = _nxc_login_ok(out)
    if ok and success:
        findings.append(success)
    elif not ok and on_fail:
        findings.append(on_fail)
    return ok


def _nxc_admin_ok(out):
    """True if netexec confirms admin/RCE-capable access ((Pwn3d!) marker)."""
    return bool(out) and "Pwn3d" in out


async def _nxc_enum(nxc, proto, host, runner, findings, port, subs, tag,
                    auth="", timeout=None, prefix="nxc"):
    """Run a batch of read-only netexec sub-commands against one host, teeing
    each to its own file and running scan_findings over the output. `subs` is a
    list of flag strings (e.g. "--shares", "-M gpp_password"). Returns a
    {sub: output} map so callers can post-process specific results. DRYs the
    repeated per-flag loops across the enum_* functions."""
    results = {}
    for sub in subs:
        head = sub.split()[0].strip("-") or "run"          # --shares -> shares
        if head == "M" and len(sub.split()) > 1:            # -M gpp_password -> gpp_password
            head = "M_" + sub.split()[1]
        cmd = f"{nxc} {proto} {host} {auth} {sub}".strip()
        rc, out = await runner.run(cmd, f"{tag}/{prefix}_{head}.txt".replace("/-", "/"),
                                   f"{nxc} {proto} {sub.split()[0]}", timeout=timeout)
        scan_findings(out, proto, port, findings)
        results[sub] = out or ""
    return results


def cred_label(args):
    who = args.user
    if getattr(args, "domain", None):
        who = f"{args.domain}\\{args.user}"
    secret = "<hash>" if getattr(args, "hash", None) else "<pass>"
    scope = "local" if getattr(args, "local_auth", False) else "domain"
    return f"{who}:{secret} ({scope})"


# --------------------------------------------------------------------------- #
#  Findings engine - regex rules over tool output
# --------------------------------------------------------------------------- #
FINDING_RULES = [
    # (severity, compiled_regex, service_hint, message_template)
    # NOTE: anonymous-FTP is NOT flagged by a loose regex here - a banner like
    # "220 Anonymous access allowed, send email as password" or nxc's own
    # failure lines would false-positive. enum_ftp() confirms it explicitly
    # (curl exit code / nmap "login allowed" / netexec "Anonymous Login!").
    ("HIGH",     re.compile(r"vsftpd 2\.3\.4", re.I), "ftp", "vsftpd 2.3.4 - backdoor (CVE-2011-2523)"),
    # Must match a *confirmed* null session, not just the phrase "null session"
    # appearing in a failure message like "Could not establish null session: ...".
    ("CRITICAL", re.compile(r"Server allows (?:session using|authenticat\w* via) username '',?\s*(?:password|and password) ''", re.I), "smb", "SMB NULL session allowed"),
    # Signing and SMBv1 are DISTINCT weaknesses - keep them as separate,
    # accurately-labelled findings. Match only an actual weak value, not just
    # the field name: netexec prints "(signing:True)"/"(SMBv1:True)" and flips
    # to False/None when safe, so "signing:True" means signing IS required
    # (NOT a finding) - the old combined rule matched SMBv1:True but mislabelled
    # it "signing disabled ... MS17-010 candidate", a false positive on any
    # modern host that merely still has SMB1 enabled.
    ("HIGH",     re.compile(r"signing:\s*False\b|SMB signing required:\s*false\b|Message signing enabled but not required|Message signing disabled", re.I), "smb", "SMB signing not required - NTLM relay candidate"),
    ("MEDIUM",   re.compile(r"SMBv1:\s*True\b|SMB1 \(enabled\)|SMB 1\.0:\s*true\b|SMB1 only:\s*true\b", re.I), "smb", "SMBv1 enabled - legacy protocol; MS17-010 surface (confirm with the ms17-010 module)"),
    ("HIGH",     re.compile(r"(READ|WRITE)(,|/| )?(WRITE)? on \\\\|Mapping: OK.*Listing: OK", re.I), "smb", "Readable/writable SMB share"),
    ("MEDIUM",   re.compile(r"\[\+\] Enumerating users", re.I), "smb", "User enumeration succeeded via RID/LSA"),
    # Only a scanner-CONFIRMED hit, never the module name/command echo or the
    # negative "does NOT appear vulnerable" line (which the old /MS17-010/ regex
    # matched, flagging every host the ms17-010 module merely ran against).
    ("HIGH",     re.compile(r"appears?\s+vulnerable\s+to\s+MS17-010|smb-vuln-ms17-010[\s\S]{0,200}?State:\s*VULNERABLE", re.I), "smb", "MS17-010 (EternalBlue) - scanner-confirmed vulnerable"),
    ("CRITICAL", re.compile(r"(anonymous|unauthenticated) bind", re.I), "ldap", "LDAP anonymous bind allowed"),
    ("HIGH",     re.compile(r"defaultNamingContext:|rootDomainNamingContext:", re.I), "ldap", "LDAP leaks naming context (domain structure)"),
    # Only netexec's explicit DC flag - the old /Domain Controller/ substring
    # matched built-in AD group names ("Domain Controllers", "Cloneable Domain
    # Controllers", ...) present in ANY authenticated LDAP groups dump, flagging
    # every domain host (not just DCs) as a Domain Controller.
    ("HIGH",     re.compile(r"\(DC:True\)", re.I), "ad", "Host looks like a Domain Controller"),
    ("MEDIUM",   re.compile(r"Kerberos.*88/tcp open", re.I), "kerberos", "Kerberos exposed - try user enum / AS-REP roasting"),
    # netexec dump/exec/AD-enum output (added for the full nxc coverage)
    ("CRITICAL", re.compile(r"\(Pwn3d!\)", re.I), "creds", "netexec: ADMIN access (Pwn3d!) - remote code execution available"),
    ("CRITICAL", re.compile(r"\$krb5asrep\$", re.I), "ad", "AS-REP roastable hash captured (netexec --asreproast) - crack offline"),
    ("CRITICAL", re.compile(r"\$krb5tgs\$", re.I), "ad", "Kerberoastable TGS hash captured (netexec --kerberoasting) - crack offline"),
    ("CRITICAL", re.compile(r"^\s*\w[\w$.-]*:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::", re.M), "creds", "NTLM hashes dumped (SAM/NTDS) - pass-the-hash / crack"),
    ("HIGH",     re.compile(r"TRUSTED_FOR_DELEGATION|Unconstrained|constrained delegation", re.I), "ad", "Kerberos delegation configured - delegation abuse path"),
    ("HIGH",     re.compile(r"PASSWD_NOTREQD|password[- ]not[- ]required|DONT_REQ_PREAUTH", re.I), "ad", "Account with weak UAC flag (no-preauth / passwd-notreqd)"),
    ("CRITICAL", re.compile(r"(LAPS|ms-mcs-admpwd).{0,40}(password|:)\s*\S{6,}", re.I), "creds", "LAPS local-admin password recovered via netexec"),
    # A RECOVERED gMSA (account + NTLM hash) or the BloodHound edge - not the
    # bare "gMSA" word (matched netexec's "[*] Getting GMSA Passwords" status
    # line and the "--gmsa" flag) which fired even when nothing was read.
    ("HIGH",     re.compile(r"ReadGMSAPassword|Account:\s*\S+\$\s+NTLM:\s*[0-9a-fA-F]{32}", re.I), "ad", "gMSA readable - managed password recovered"),
    ("CRITICAL", re.compile(r"cpassword|gpp_password.*found|Found credentials in", re.I), "creds", "GPP cpassword / autologin credential found in SYSVOL"),
    # Only a real ESC hit / vulnerable-template verdict - the old "adcs.*Enrollment"
    # alternation matched netexec's "[*] Starting LDAP search ... pKIEnrollmentService"
    # status line, flagging a vulnerable template before anything was found.
    ("HIGH",     re.compile(r"\bESC\d{1,2}\b|Vulnerable Certificate Templates?", re.I), "ad", "AD CS vulnerable template (ESC) - certipy"),
    # requires an explicit credential-assignment keyword + ':'/'=' + a value,
    # not just two words separated by punctuation (that matched web paths
    # like "admin/config" and any "word: word" text as false positives). The
    # (?<!empty-)/(?<!empty_) guards stop it matching tool/NSE script names like
    # "mysql-empty-password: Host ..." (keyword is part of the script name, not
    # a leaked credential).
    ("HIGH",     re.compile(r"(?:^|[^a-zA-Z0-9])(?<!empty-)(?<!empty_)(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)['\"]?\s*[:=]\s*['\"]?\S{3,}", re.I), "creds", "Possible default/leaked credential in output"),
    ("MEDIUM",   re.compile(r"robots\.txt", re.I), "http", "robots.txt present - inspect disallowed paths"),
    # (?<!\.) blocks matches touching a dot, so a "firstname.jenkins" or
    # "firstname.gitlab"-style domain username (seen in SMB/LDAP user dumps)
    # doesn't get misread as a Jenkins/GitLab web app or path.
    # /admin\b and /api\b are word-anchored so they match the real paths but NOT
    # /Administrator - without the \b, an nxc --lsa / --sam dump line like
    # "DOMAIN/Administrator:$DCC2$..." matched "/admin" and surfaced the box's
    # most valuable loot as a bogus "web path" on the wrong service/port.
    ("HIGH",     re.compile(r"(?<!\.)(phpmyadmin|/admin\b|wp-login|wp-admin|/manager/html|jenkins|gitlab|/api\b|/backup)", re.I), "http", "Interesting web path discovered"),
    ("HIGH",     re.compile(r"(?<!\.)(Apache Tomcat|Jenkins|GitLab|WordPress|Drupal|Joomla)[\s/]*([\d.]+)?", re.I), "http", "Notable web application detected"),
    ("MEDIUM",   re.compile(r"Server: .*(IIS|Apache|nginx)[/ ]([\d.]+)", re.I), "http", "Web server banner reveals version"),
    ("MEDIUM",   re.compile(r"(index of /|directory listing)", re.I), "http", "Directory listing enabled"),
    ("HIGH",     re.compile(r"snmp.*public|Community.*public|::public", re.I), "snmp", "SNMP community 'public' - walk it for creds/processes"),
    ("MEDIUM",   re.compile(r"showmount.*\*|/\w+ \*", re.I), "nfs", "NFS export world-readable (showmount)"),
    ("HIGH",     re.compile(r"redis.*(no password|NOAUTH|-ERR.*without)|Ready to accept", re.I), "redis", "Redis reachable without auth"),
    ("HIGH",     re.compile(r"MSSQL.*(sa|1433).*login|Login failed for user 'sa'", re.I), "mssql", "MSSQL exposed - test sa / weak creds"),
    ("MEDIUM",   re.compile(r"VRFY \d{3}|252 |250 2\.1\.5", re.I), "smtp", "SMTP VRFY/EXPN user enumeration possible"),
    ("INFO",     re.compile(r"OpenSSH ([\d.]+)", re.I), "ssh", "SSH version noted (check for user enum CVE-2018-15473)"),
    # PostgreSQL
    ("CRITICAL", re.compile(r"\[\+\].*postgres.*\(Pwn3d!\)|Login successful.*postgres|Authentication succeeded", re.I), "postgres", "PostgreSQL default/blank credentials accepted"),
    ("CRITICAL", re.compile(r"List of databases|\btemplate1\b|\btemplate0\b", re.I), "postgres", "PostgreSQL unauthenticated access - database list dumped"),
    ("HIGH",     re.compile(r"pgsql|PostgreSQL \d|psql \(", re.I), "postgres", "PostgreSQL reachable - test postgres/blank and weak creds"),
    ("MEDIUM",   re.compile(r"fe_sendauth: no password supplied|no pg_hba\.conf entry", re.I), "postgres", "PostgreSQL requires auth (note pg_hba details in output)"),
    # MySQL - one precise rule for the exact nmap NSE empty-password phrase.
    # Reachability / host-restriction / default-cred findings are emitted by
    # enum_mysql() itself, so no broad "reachable" regex here (avoids FPs).
    ("CRITICAL", re.compile(r"account has empty password", re.I), "mysql", "MySQL account with EMPTY password (nmap mysql-empty-password)"),
    # POP3 / IMAP
    ("HIGH",     re.compile(r"USER command used|\+OK.*USER|SASL.*(LOGIN|PLAIN)", re.I), "pop3", "POP3 supports USER/PASS or PLAIN auth - test cred reuse"),
    ("HIGH",     re.compile(r"CAPABILITY.*(LOGIN|AUTH=PLAIN|AUTH=LOGIN)|\* OK.*IMAP", re.I), "imap", "IMAP allows LOGIN/PLAIN auth - test cred reuse"),
    ("MEDIUM",   re.compile(r"STARTTLS", re.I), "mail", "STARTTLS offered - creds encrypted in transit but still testable"),
    ("INFO",     re.compile(r"Dovecot|Courier|Cyrus|UW-IMAP", re.I), "mail", "Mail server software identified (check version CVEs)"),
    # Authenticated / credentialed results (netexec style output)
    ("CRITICAL", re.compile(r"\(Pwn3d!\)", re.I), "creds", "ADMIN access with these credentials (Pwn3d!) - you can get a shell / dump SAM"),
    ("HIGH",     re.compile(r"\[\+\]\s+\S+\\\S+:\S+", re.I), "creds", "Credentials VALID on this service - reuse them across every host"),
    ("HIGH",     re.compile(r"\bSTATUS_ACCOUNT_LOCKED_OUT\b", re.I), "creds", "ACCOUNT LOCKED OUT - stop spraying this user immediately"),
    ("MEDIUM",   re.compile(r"\bSTATUS_PASSWORD_EXPIRED\b", re.I), "creds", "Password expired but valid - may be changeable via SMB/RDP"),
    ("INFO",     re.compile(r"\bSTATUS_LOGON_FAILURE\b", re.I), "creds", "Credentials rejected on this service"),
]


# Services whose output legitimately carries web content. HTTP-specific rules
# (web paths, app/server banners) are applied ONLY to these - run against an
# SMB/WinRM/LDAP/MSSQL dump they mislabel unrelated text as a web finding on the
# wrong port (defence-in-depth alongside the word-anchored web-path regex).
_WEB_CONTEXT_SERVICES = {"http", "vuln"}


def scan_findings(text, default_service, port, findings):
    web_ctx = default_service in _WEB_CONTEXT_SERVICES
    for sev, rx, svc_hint, msg in FINDING_RULES:
        if svc_hint == "http" and not web_ctx:
            continue
        m = rx.search(text)
        if m:
            findings.append(Finding(sev, svc_hint or default_service, port, msg))


# Juicy filenames worth flagging when spider_plus inventories a share - the
# files that most often hold creds/keys on an OSCP box. Each spidered file
# PATH is tested against these (case-insensitive), most valuable first; the
# first match wins so one file yields one finding at its highest severity.
# This is a filename heuristic only - reconx never opens/downloads the files.
_SPIDER_JUICY_RULES = [
    ("CRITICAL", re.compile(r"(?:^|[\\/])(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(kdbx?|ppk|pem|pfx|p12)$", re.I),
     "private key / password vault"),
    ("CRITICAL", re.compile(r"(?:^|[\\/])(groups\.xml|unattend\.xml|autounattend\.xml|sysprep\.(inf|xml)|web\.config)$", re.I),
     "config with embedded/recoverable creds"),
    ("HIGH", re.compile(r"(?:^|[\\/])(\.git-credentials|\.npmrc|\.env|credentials?|secrets?)(\.\w+)?$|passwo?r?d|\.(ovpn|rdp)$", re.I),
     "credential-bearing file"),
    ("MEDIUM", re.compile(r"\.(bak|old|sql|dump)$|backup", re.I),
     "backup / dump (may hold creds or data)"),
    ("MEDIUM", re.compile(r"\.(ps1|bat|cmd|vbs|sh)$", re.I),
     "script (often hardcodes creds/paths)"),
]


def _spider_findings(spider_json, findings, limit=40):
    """Parse a netexec spider_plus JSON inventory ({share: {path: meta}}) and
    flag juicy files by name via _SPIDER_JUICY_RULES. Names the share + path so
    the finding is actionable. Caps at `limit` hits so a share full of e.g.
    .bak files can't drown the summary. Degrades silently on a missing/odd file."""
    try:
        with open(spider_json, errors="replace") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    if not isinstance(data, dict):
        return
    hits = 0
    for share, files in data.items():
        if not isinstance(files, dict):
            continue
        for path in files:
            for sev, rx, why in _SPIDER_JUICY_RULES:
                if rx.search(path):
                    findings.append(Finding(sev, "smb", 445,
                        f"Juicy file on \\\\{share}: {path} ({why})"))
                    hits += 1
                    break
            if hits >= limit:
                warn(f"spider: {limit}+ juicy files flagged - review {spider_json} for the rest")
                return


# --------------------------------------------------------------------------- #
#  Enumeration modules - each returns nothing, appends to findings list
# --------------------------------------------------------------------------- #
async def _nmap_nse(host, port, scripts, proto, runner, tag, findings, timeout=None):
    """Run an nmap NSE script set against one port, save output to
    <tag>/<proto>_nse.txt, and scan it into findings. Returns the raw output
    text for callers that need to inspect it further (e.g. RDP NTLM info)."""
    rc, out = await runner.run(
        f"nmap -Pn -p {port} --script {scripts} -oN /dev/stdout {host}",
        f"{tag}/{proto}_nse.txt", f"nmap-{proto}", timeout=timeout)
    scan_findings(out, proto, port, findings)
    return out


_SMB_BANNER_NAME_RX = re.compile(r"\(name:([^)]*)\)")
_SMB_BANNER_DOMAIN_RX = re.compile(r"\(domain:([^)]*)\)")
_SMB_BANNER_ISDC_RX = re.compile(r"\(DC:True\)")


def _hosts_line_from_banner(host, out):
    """Build netexec's own hosts-line format from an SMB banner line, e.g.
    'SMB ... (name:DC) (domain:northstone.local) ... (DC:True)' ->
    '<ip>  DC.northstone.local northstone.local DC'. Returns '' if the banner
    lacks a usable name/domain. Mirrors netexec: the bare domain only appears
    (as the middle field) for a Domain Controller."""
    nm = _SMB_BANNER_NAME_RX.search(out or "")
    dm = _SMB_BANNER_DOMAIN_RX.search(out or "")
    if not (nm and dm and nm.group(1) and dm.group(1)):
        return ""
    name, domain = nm.group(1).strip(), dm.group(1).strip()
    # name/domain come from an attacker-controlled SMB banner and land verbatim in
    # an /etc/hosts line. The (name:...)/(domain:...) capture is [^)]*, which also
    # matches whitespace/newlines - a crafted banner could smuggle extra hosts
    # entries. Real names are [A-Za-z0-9.-]; reject anything else outright.
    if not (re.fullmatch(r"[A-Za-z0-9.-]+", name) and re.fullmatch(r"[A-Za-z0-9.-]+", domain)):
        return ""
    dc_part = f" {domain}" if _SMB_BANNER_ISDC_RX.search(out or "") else ""
    return f"{host}     {name}.{domain}{dc_part} {name}"


async def _smb_hosts_file(nxc, host, runner, args, findings):
    """Emit an ACCURATE /etc/hosts line straight from the SMB banner via
    netexec's --generate-hosts-file, instead of guessing the domain from a
    reverse-PTR label (often wrong). netexec writes the line during host-info
    enumeration, so it works over a null/guest session:
        IP    HOSTNAME.domain [domain-if-DC] HOSTNAME
    Add the whole line to /etc/hosts in one shot - no need to hand-assemble it.

    Robustness: netexec's first invocation can transiently return nothing under
    reconx's concurrency (cold DB init), so we retry once; and if it printed the
    banner but wrote no file (e.g. the guest login errored STATUS_ACCOUNT_DISABLED
    before the file write on some paths), we assemble the identical line from the
    banner ourselves."""
    tag = f"{host}/smb"
    hosts_path = os.path.join(runner.hostdir(host), "smb", "hosts")
    auth = nxc_auth(args) if have_creds(args) else "-u guest -p ''"

    def _read_line():
        try:
            with open(hosts_path, errors="replace") as f:
                return f.read().strip()
        except OSError:
            return ""

    async def _attempt():
        # netexec appends (a+); drop a stale file first so we read back exactly
        # this host's line and don't accumulate duplicates across retries/resume.
        if not runner.dry_run:
            try:
                os.makedirs(os.path.dirname(hosts_path), exist_ok=True)
                if os.path.exists(hosts_path):
                    os.remove(hosts_path)
            except OSError:
                pass
        _, out = await runner.run(
            f"{nxc} smb {host} {auth} --generate-hosts-file {shlex.quote(hosts_path)}",
            f"{tag}/nxc_hosts.txt", f"{nxc} smb --generate-hosts-file")
        return out or ""

    out = await _attempt()
    if runner.dry_run:
        return
    line = _read_line()
    # nothing at all (not even a banner) -> transient; one serial retry.
    if not line and not _SMB_BANNER_NAME_RX.search(out):
        out = await _attempt()
        line = _read_line()
    # banner seen but no file written -> build the line ourselves.
    if not line:
        line = _hosts_line_from_banner(host, out)
        if line:
            try:
                with open(hosts_path, "w") as f:
                    f.write(line + "\n")
            except OSError:
                pass
    if line:
        findings.append(Finding("INFO", "smb", 445,
            f"/etc/hosts entry (SMB-derived, accurate): {line}   "
            f"(sudo sh -c 'echo \"{line}\" >> /etc/hosts'; saved to {hosts_path})"))


async def enum_smb(host, runner, args, findings):
    tag = f"{host}/smb"
    nxc = nxc_bin()
    if nxc:
        await _smb_hosts_file(nxc, host, runner, args, findings)
    if have_creds(args):
        # authenticated: check access, admin (Pwn3d!), shares, users, and loot.
        if nxc:
            auth = nxc_auth(args)
            # Read-only enumeration: host/domain, shares, all principals, policy,
            # sessions, disks, interfaces, LAPS read, plus GPP cpassword / AV /
            # autologin modules (SYSVOL creds are a classic OSCP win).
            enum_subs = ("--shares", "--users", "--groups", "--local-groups",
                         "--pass-pol", "--rid-brute", "--smb-sessions",
                         "--loggedon-users", "--disks", "--computers",
                         "--interfaces", "--qwinsta", "--laps",
                         "-M enum_av", "-M gpp_password", "-M gpp_autologin")
            res = await _nxc_enum(nxc, "smb", host, runner, findings, 445, enum_subs,
                                  tag, auth=auth, prefix="auth_nxc")
            admin = _nxc_admin_ok(res.get("--shares", ""))
            # Credential dumping (Full mode): SAM + LSA secrets + DPAPI. --ntds
            # dumps the whole domain hash store and only works on a DC, so it is
            # gated on confirmed admin (nxc errors harmlessly on a non-DC).
            await _nxc_enum(nxc, "smb", host, runner, findings, 445,
                            ("--sam", "--lsa", "--dpapi"), tag, auth=auth,
                            prefix="auth_nxc")
            if admin:
                await _nxc_enum(nxc, "smb", host, runner, findings, 445,
                                ["--ntds"], tag, auth=auth, prefix="auth_nxc",
                                timeout=args.enum_timeout)
                # Command execution proof (Full mode): only with admin/Pwn3d.
                for cmd in ("whoami", "hostname"):
                    rc, out = await runner.run(f"{nxc} smb {host} {auth} -x {shlex.quote(cmd)}",
                                               f"{tag}/auth_nxc_exec_{cmd}.txt", f"{nxc} smb -x {cmd}")
                    scan_findings(out, "smb", 445, findings)
                findings.append(Finding("CRITICAL", "smb", 445,
                    f"SMB RCE as admin: {nxc} smb {host} {cred_label(args)} -x whoami "
                    f"(also: impacket psexec/wmiexec/smbexec)"))
            # Spider readable shares for accessible files - creds live in share
            # CONTENT, not share names. spider_plus is metadata-only (no download
            # by default) and writes a full per-file JSON inventory into the box's
            # smb/ dir; we tee its stdout summary and scan it for findings. Slow on
            # big shares, so it gets the longer enum timeout and runs last.
            spider_dir = os.path.join(runner.hostdir(host), "smb")
            rc, out = await runner.run(
                f"{nxc} smb {host} {auth} -M spider_plus -o OUTPUT_FOLDER='{spider_dir}'",
                f"{tag}/auth_nxc_spider_plus.txt", f"{nxc} smb -M spider_plus",
                timeout=args.enum_timeout)
            scan_findings(out, "smb", 445, findings)
            # Rank juicy files out of the inventory spider_plus just wrote
            # (filename heuristic only - files aren't opened). The exact JSON
            # name is version-dependent, so scan any .json in the smb/ dir.
            for sj in glob.glob(os.path.join(spider_dir, "*.json")):
                _spider_findings(sj, findings)
        else:
            findings.append(Finding("MEDIUM", "smb", 445,
                "Creds supplied but no netexec/nxc found - authenticated SMB untested"))
    elif nxc:
        # Unauthenticated: null session first (read-only), then a guest fallback.
        # --rid-brute over a null/guest session is the big win for user enum.
        null_subs = ("--shares", "--users", "--pass-pol", "--rid-brute",
                     "--smb-sessions", "--loggedon-users", "--groups", "-M ms17-010")
        await _nxc_enum(nxc, "smb", host, runner, findings, 445, null_subs, tag,
                        auth="-u '' -p ''", prefix="nxc")
        await _nxc_enum(nxc, "smb", host, runner, findings, 445,
                        ("--shares", "--rid-brute"), tag,
                        auth="-u guest -p ''", prefix="nxc_guest")
    if TOOLS.get("enum4linux-ng"):
        rc, out = await runner.run(f"enum4linux-ng -A {host}", f"{tag}/enum4linux-ng.txt", "enum4linux-ng",
                                   timeout=args.enum_timeout)
        scan_findings(out, "smb", 445, findings)
    elif TOOLS.get("enum4linux"):
        rc, out = await runner.run(f"enum4linux -a {host}", f"{tag}/enum4linux.txt", "enum4linux",
                                   timeout=args.enum_timeout)
        scan_findings(out, "smb", 445, findings)
    if TOOLS.get("smbclient"):
        rc, out = await runner.run(f"smbclient -N -L //{host}/", f"{tag}/smbclient_list.txt", "smbclient")
        scan_findings(out, "smb", 445, findings)
    good("smb enum done")


def _dn_to_domain(dn):
    """'DC=checkpoint,DC=htb' -> 'checkpoint.htb'"""
    parts = re.findall(r"DC=([^,]+)", dn or "", re.I)
    return ".".join(parts) if parts else None


def _impacket_bin(name):
    """Kali packages these as impacket-<Name>; some installs keep the raw
    <Name>.py script name instead - try both, skip gracefully if neither."""
    return _first_tool(f"impacket-{name}", f"{name}.py")


_NXC_USER_ROW_RX = re.compile(r"^\S+\s+\S+\s+\d+\s+\S+\s+(\S+)\s+(?:\d{4}-\d{2}-\d{2}|<never>)", re.M)
_KRB5TGS_RX = re.compile(r"\$krb5tgs\$\d+\$\*?([^\s*$]+)")
_KRB5ASREP_RX = re.compile(r"\$krb5asrep\$\d+\$([^\s:]+)")


async def _impacket_roast_check(host, dom, runner, args, findings, tag, users_out):
    """Cross-checks nxc's --kerberoasting/--asreproast with impacket's own
    GetUserSPNs/GetNPUsers. Worth doing separately, not redundant: nxc
    auto-derives the real LDAP search base from the DC's own rootDSE no
    matter what --domain string it's given, while impacket's tools build the
    search base directly from the domain string passed in - so a wrong or
    mistyped --domain silently breaks impacket's tools with a confusing LDAP
    referral error even when nxc's own check looked completely fine. That's
    exactly the failure mode that prompted adding this cross-check, so `dom`
    should be the domain derived from rootDSE (see _dn_to_domain), not raw
    args.domain, whenever the former is available."""
    if not dom:
        return
    loot_dir = os.path.join(runner.hostdir(host), "ldap", "loot")
    if not runner.dry_run:
        os.makedirs(loot_dir, exist_ok=True)

    spn_bin = _impacket_bin("GetUserSPNs")
    np_bin = _impacket_bin("GetNPUsers")
    if not spn_bin and not np_bin:
        findings.append(Finding("INFO", "ldap", None,
            "impacket's GetUserSPNs/GetNPUsers not found - Kerberoast/AS-REP cross-check skipped"))
        return

    async def _run_getuserspns():
        if not spn_bin:
            return
        user = f"{dom}/{args.user}"
        if getattr(args, "hash", None):
            target, hash_flag = shlex.quote(user), f"-hashes {shlex.quote(args.hash)}"
        else:
            target, hash_flag = shlex.quote(f"{user}:{args.password}"), ""
        out_file = os.path.abspath(os.path.join(loot_dir, "kerb_impacket.txt"))
        cmd = (f"{spn_bin} {target} {hash_flag} -dc-ip {host} -request "
               f"-outputfile {shlex.quote(out_file)}").replace("  ", " ")
        rc, out = await runner.run(cmd, f"{tag}/impacket_getuserspns.txt", "GetUserSPNs",
                                   timeout=args.enum_timeout)
        hits = sorted(set(_KRB5TGS_RX.findall(out or "")))
        if hits:
            findings.append(Finding("CRITICAL", "ldap", None,
                f"Kerberoastable account(s) via GetUserSPNs: {', '.join(hits)} - "
                f"hash(es) saved to {out_file}, crack with hashcat -m 13100"))

    async def _run_getnpusers():
        users = sorted(set(_NXC_USER_ROW_RX.findall(users_out or "")))
        if not (np_bin and users):
            return
        users_file = os.path.join(loot_dir, "_candidate_users.txt")
        if not runner.dry_run:
            with open(users_file, "w") as f:
                f.write("\n".join(users) + "\n")
        out_file = os.path.abspath(os.path.join(loot_dir, "asrep_impacket.txt"))
        cmd = (f"{np_bin} {shlex.quote(dom + '/')} -usersfile {shlex.quote(users_file)} -no-pass "
               f"-dc-ip {host} -request -outputfile {shlex.quote(out_file)}")
        rc, out = await runner.run(cmd, f"{tag}/impacket_getnpusers.txt", "GetNPUsers",
                                   timeout=args.enum_timeout)
        hits = sorted(set(_KRB5ASREP_RX.findall(out or "")))
        if hits:
            findings.append(Finding("CRITICAL", "ldap", None,
                f"AS-REP roastable account(s) via GetNPUsers: {', '.join(hits)} - "
                f"hash(es) saved to {out_file}, crack with hashcat -m 18200"))

    # independent checks (different tools, no shared state) - run concurrently.
    # return_exceptions=True so a failure in one doesn't leave the other as an
    # orphaned task that JobQueue never awaits/cleans up. Check BaseException,
    # not Exception - asyncio.CancelledError is a BaseException (3.8+) and a
    # cancelled child would otherwise be silently treated as a clean finish.
    results = await asyncio.gather(_run_getuserspns(), _run_getnpusers(), return_exceptions=True)
    errors = [r for r in results if isinstance(r, BaseException)]
    for e in errors:
        warn(f"{host}: kerberoast/asreproast check failed - {e}")
    if errors:
        real = next((e for e in errors if isinstance(e, Exception)), None)
        if real:
            raise real
        return
    good(f"{host}: impacket kerberoast/asreproast cross-check done")


def _bloodhound_bin():
    return _first_tool("bloodhound-python", "bloodhound-ce-python")


async def enum_bloodhound(host, dom, runner, args, findings):
    """Background job (--bloodhound): full BloodHound collection (-c All).
    Registered from enum_ldap() once it knows the DC's real domain (see
    _dn_to_domain), not from register_service_jobs() - the domain isn't
    known until the rootDSE lookup inside enum_ldap() runs.

    Explicitly points -ns (nameserver) at the DC itself rather than relying
    on this machine's default DNS: bloodhound-python resolves every
    computer object it finds, so a wrong/absent DNS server breaks that
    silently across the whole collection - the same class of failure the
    domain-typo cross-check above exists to catch for impacket's tools."""
    bin_name = _bloodhound_bin()
    if not bin_name or not dom:
        return
    bh_dir = os.path.join(runner.hostdir(host), "ldap", "bloodhound")
    if not runner.dry_run:
        os.makedirs(bh_dir, exist_ok=True)
    if getattr(args, "hash", None):
        auth = f"--hashes {shlex.quote(args.hash)}"
    else:
        auth = f"-p {shlex.quote(args.password)}"
    cmd = (f"cd {shlex.quote(bh_dir)} && {bin_name} -u {shlex.quote(args.user + '@' + dom)} {auth} "
           f"-d {shlex.quote(dom)} -ns {host} -c All --zip")
    outfile = f"{host}/ldap/bloodhound_collect.txt"
    rc, out = await runner.run(cmd, outfile, "bloodhound", timeout=args.scan_timeout)
    if rc == 0:
        findings.append(Finding("HIGH", "ad", None,
            f"BloodHound collection complete - load the .zip from {bh_dir} into BloodHound and hunt for attack paths"))
    elif not runner.dry_run:
        # surface failure as a finding too, not just a log line buried in
        # outfile - e.g. LDAP signing enforced + LDAPS unreachable/reset is
        # a real failure mode seen in testing, distinct from "just missing
        # a tool" and easy to miss if only the raw output file has it
        findings.append(Finding("MEDIUM", "ad", None,
            f"BloodHound collection failed (exit {rc}) - see {outfile} for details"))
    good(f"{host}: BloodHound collection done")


async def enum_ldap(host, port, runner, args, findings, queue):
    tag = f"{host}/ldap"
    real_domain = None
    if TOOLS.get("ldapsearch"):
        rc, out = await runner.run(
            f"ldapsearch -x -H ldap://{host}:{port} -s base -b '' namingContexts defaultNamingContext",
            f"{tag}/rootdse.txt", "ldap-rootdse")
        scan_findings(out, "ldap", port, findings)
        # try to pull naming context and dump anonymously
        m = re.search(r"(?:defaultNamingContext|namingContexts):\s*(DC=[^\n]+)", out or "", re.I)
        if m:
            base = m.group(1).strip()
            real_domain = _dn_to_domain(base)
            findings.append(Finding("HIGH", "ldap", port, f"LDAP base found: {base}"))
            rc, out2 = await runner.run(
                # base comes from the target's rootDSE; shlex.quote it rather than
                # wrapping in a literal '...' (an embedded quote would break out).
                f"ldapsearch -x -H ldap://{host}:{port} -b {shlex.quote(base)}",
                f"{tag}/anon_dump.txt", "ldap-dump", timeout=args.enum_timeout)
            scan_findings(out2, "ldap", port, findings)
    # authenticated: netexec LDAP enum + kerberoast/asreproast cross-check + BloodHound hint
    if have_creds(args):
        nxc = nxc_bin()
        dom = real_domain or args.domain or "<domain>"
        if real_domain and args.domain and real_domain.lower() != args.domain.lower():
            findings.append(Finding("INFO", "ldap", port,
                f"--domain '{args.domain}' doesn't match the DC's real domain '{real_domain}' "
                f"(from rootDSE) - using '{real_domain}' for the LDAP-derived checks below"))
        users_out = ""
        if nxc:
            auth = nxc_auth(args)
            loot_dir = os.path.join(runner.hostdir(host), "ldap", "loot")
            if not runner.dry_run:
                os.makedirs(loot_dir, exist_ok=True)
            asrep_out = os.path.abspath(os.path.join(loot_dir, "asrep.txt"))
            kerb_out = os.path.abspath(os.path.join(loot_dir, "kerb.txt"))
            # Full AD enumeration: principals, roast, delegation, weak-UAC
            # accounts, SID, gMSA, DC list, subnets, plus high-value modules
            # (adcs/ESC, MachineAccountQuota, whoami, user descriptions - which
            # frequently hold passwords).
            ldap_subs = ("--users", "--groups", "--admin-count",
                         "--trusted-for-delegation", "--find-delegation",
                         "--password-not-required", "--get-sid", "--gmsa",
                         "--dc-list", "--pass-pol",
                         f"--asreproast {shlex.quote(asrep_out)}",
                         f"--kerberoasting {shlex.quote(kerb_out)}",
                         "-M adcs", "-M maq", "-M whoami",
                         "-M get-desc-users", "-M subnets")
            res = await _nxc_enum(nxc, "ldap", host, runner, findings, port,
                                  ldap_subs, tag, auth=auth, prefix="auth_ldap")
            users_out = res.get("--users", "")
        real_dom = dom if dom != "<domain>" else None
        await _impacket_roast_check(host, real_dom, runner, args, findings, tag, users_out)
        if args.bloodhound and real_dom:
            queue.add_job(Job(f"{host}:bloodhound", PRIO_BACKGROUND, background=True,
                coro_factory=functools.partial(enum_bloodhound, host, real_dom, runner, args, findings)))
        else:
            findings.append(Finding("HIGH", "ad", port,
                f"Authenticated to LDAP - run BloodHound now: "
                f"bloodhound-python -u {args.user}@{dom} -p <pass> -d {dom} -ns {host} -c All"))
    good("ldap enum done")


async def enum_ftp(host, port, runner, args, findings):
    """Anonymous login is only flagged on POSITIVE proof, from any of three
    independent sources, so a chatty banner ("Anonymous access allowed, send
    email as password") or a tool's failure message can't false-positive it:
      - nmap ftp-anon prints "Anonymous FTP login allowed",
      - curl exits 0 (login AND the LIST both succeeded), or
      - netexec prints its "- Anonymous Login!" success line."""
    tag = f"{host}/ftp_{port}"
    anon_ok = False
    evidence = None
    if TOOLS.get("nmap"):
        out = await _nmap_nse(host, port, "ftp-anon,ftp-syst", "ftp", runner, tag, findings)
        if out and re.search(r"ftp-anon:.*login allowed", out, re.I):
            anon_ok, evidence = True, "nmap ftp-anon"
    if TOOLS.get("curl"):
        # -sS keeps the failure reason in the saved file; the finding is gated
        # on curl's exit code, which is 0 ONLY when the anonymous login and the
        # directory LIST both succeed (an empty listing still exits 0 = allowed).
        rc, out = await runner.run(f"curl -sS --max-time 15 ftp://anonymous:anonymous@{host}:{port}/",
                                   f"{tag}/anon_list.txt", "ftp-anon-curl")
        if rc == 0:
            anon_ok = True
            evidence = evidence or "curl directory listing"
    nxc = nxc_bin()
    if nxc:
        # nxc lists the tree with supplied creds, and gives a second opinion on
        # anonymous access alongside nmap/curl.
        if have_creds(args):
            await _nxc_enum(nxc, "ftp", host, runner, findings, port, ("--ls",),
                            tag, auth=nxc_auth(args), prefix="auth_nxc")
        rc, out = await runner.run(f"{nxc} ftp {host} -u anonymous -p '' --ls",
                                   f"{tag}/nxc_anon.txt", f"{nxc} ftp anon")
        # Only netexec's explicit success line counts - not a banner that merely
        # contains the word "anonymous", and not nxc's "(Response: ...)" failures.
        if out and re.search(r"-\s*Anonymous Login!", out, re.I):
            anon_ok = True
            evidence = evidence or "netexec"
        scan_findings(out, "ftp", port, findings)   # still catches vsftpd 2.3.4 etc.
    if anon_ok:
        findings.append(Finding("CRITICAL", "ftp", port,
            f"Anonymous FTP login allowed ({evidence}) - pull every file, "
            f"check for creds/config/web-root overlap"))
    good("ftp enum done")


async def enum_ssh(host, port, runner, args, findings):
    tag = f"{host}/ssh_{port}"
    if TOOLS.get("nmap"):
        await _nmap_nse(host, port, "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey", "ssh", runner, tag, findings)
    # authenticated: validate the credential over SSH via netexec (no brute; single try)
    if have_creds(args) and not getattr(args, "hash", None):
        nxc = nxc_bin()
        if nxc:
            ssh_auth = f"-u {shlex.quote(args.user)} -p {shlex.quote(args.password)}"
            ok = await _nxc_authed_check(nxc, "ssh", host, port, runner, findings, args,
                f"{tag}/auth_nxc_ssh.txt", "nxc-ssh", auth=ssh_auth,
                success=Finding("CRITICAL", "ssh", port,
                    f"SSH login works: ssh {args.user}@{host}  (then sudo -l, id, enumerate)"))
            if ok:
                # Full mode: sudo-rights check and command-execution proof.
                await _nxc_enum(nxc, "ssh", host, runner, findings, port,
                                ("--sudo-check",), tag, auth=ssh_auth, prefix="auth_nxc")
                rc, out = await runner.run(f"{nxc} ssh {host} {ssh_auth} -x id",
                                           f"{tag}/auth_nxc_exec_id.txt", f"{nxc} ssh -x id")
                scan_findings(out, "ssh", port, findings)
    good("ssh enum done")


# SNMP is reachable both as 161/tcp (rare) and 161/udp (the common case), so
# enum_snmp can be triggered from the TCP dispatcher and from the UDP scan.
# Guard so a host that shows both doesn't get walked twice. (asyncio is
# cooperative - the check+add below is race-free with no await between them.)
_SNMP_DONE = set()


async def enum_snmp(host, runner, args, findings):
    if host in _SNMP_DONE:
        return
    _SNMP_DONE.add(host)
    tag = f"{host}/snmp"
    if TOOLS.get("onesixtyone"):
        rc, out = await runner.run(f"onesixtyone {host} public private community",
                                   f"{tag}/onesixtyone.txt", "onesixtyone")
        scan_findings(out, "snmp", 161, findings)
    if TOOLS.get("snmpwalk"):
        rc, out = await runner.run(f"snmpwalk -v2c -c public -t 3 -r 1 {host}",
                                   f"{tag}/snmpwalk_public.txt", "snmpwalk", timeout=args.enum_timeout)
        if out and "Timeout" not in out and out.strip():
            findings.append(Finding("HIGH", "snmp", 161, "SNMP 'public' community responds - walk for creds/processes/users"))
            scan_findings(out, "snmp", 161, findings)
    good("snmp enum done")


# candidate username wordlists for smtp-user-enum, checked in order - nmap's
# own smtp-enum-users NSE script (run unconditionally below) only tries a
# tiny built-in list, so this dedicated pass with a real wordlist is what
# actually finds accounts on a server that supports VRFY/EXPN/RCPT TO.
_SMTP_USER_WORDLISTS = [
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/metasploit-framework/data/wordlists/unix_users.txt",
    "/usr/share/wordlists/metasploit/unix_users.txt",
]


def _smtp_userlist():
    return _first_existing_file(_SMTP_USER_WORDLISTS)


_SMTP_ENUM_USER_RX = re.compile(r":\s*(\S+)\s+exists\b", re.I)

# tried in order, most reliable/quietest first: VRFY works on most
# misconfigured servers and is a single round-trip per user; EXPN (mailing
# list expansion) and RCPT (probing MAIL/RCPT TO during a fake delivery) are
# fallbacks for servers that disable VRFY (e.g. Postfix by default) but still
# leak via one of the others.
_SMTP_ENUM_MODES = ("VRFY", "EXPN", "RCPT")


async def enum_smtp(host, port, runner, args, findings):
    tag = f"{host}/smtp_{port}"
    if TOOLS.get("nmap"):
        await _nmap_nse(host, port, "smtp-commands,smtp-enum-users,smtp-open-relay", "smtp", runner, tag, findings)
    if TOOLS.get("smtp-user-enum"):
        userlist = _smtp_userlist()
        if userlist:
            for mode in _SMTP_ENUM_MODES:
                cmd = f"smtp-user-enum -m {mode} -U {shlex.quote(userlist)} -h {host} -p {port}"
                if mode == "RCPT" and getattr(args, "domain", None):
                    # RCPT TO:<user> alone only works when the server does
                    # local delivery unqualified; give it user@domain too
                    # (needed for Exchange-style targets) whenever we know one.
                    cmd += f" -D {shlex.quote(args.domain)}"
                rc2, out2 = await runner.run(cmd, f"{tag}/smtp-user-enum_{mode.lower()}.txt",
                                             f"smtp-user-enum-{mode.lower()}", timeout=args.enum_timeout)
                users = sorted(set(_SMTP_ENUM_USER_RX.findall(out2 or "")))
                if users:
                    shown = ", ".join(users[:10])
                    more = f" (+{len(users) - 10} more)" if len(users) > 10 else ""
                    findings.append(Finding("HIGH", "smtp", port,
                        f"SMTP user enumeration ({mode}) confirmed account(s): {shown}{more} - "
                        f"reuse as usernames against SSH/web/mail login"))
                    break  # first successful mode wins; no need to probe weaker methods too
        else:
            findings.append(Finding("INFO", "smtp", port,
                "smtp-user-enum installed but no username wordlist found - user enum skipped"))
    good("smtp enum done")


async def enum_dns(host, port, runner, args, findings):
    """Version/PTR probe, then AXFR (zone transfer) attempts against every
    domain we can find: an explicit -d/--domain, and whatever the reverse
    PTR lookup suggests (strip the leftmost label off the PTR hostname to
    guess its zone). A misconfigured NS handing out a full zone on an
    unauthenticated AXFR is a common, high-value miss if left as a manual
    step."""
    tag = f"{host}/dns_{port}"
    if not TOOLS.get("dig"):
        return
    rc, out = await runner.run(f"dig @{host} -p {port} version.bind chaos txt +short",
                               f"{tag}/version.txt", "dig-version")
    rc2, out2 = await runner.run(f"dig @{host} -p {port} -x {host} +short",
                                 f"{tag}/ptr.txt", "dig-ptr")

    domains = []
    if getattr(args, "domain", None):
        domains.append(args.domain)
    for line in (out2 or "").splitlines():
        ptr = line.strip().rstrip(".")
        if not ptr:
            continue
        labels = ptr.split(".")
        if len(labels) > 2:
            domains.append(".".join(labels[1:]))  # strip host label -> guessed zone
        elif len(labels) == 2:
            domains.append(ptr)

    tried = set()
    for dom in domains:
        dom = dom.lower()
        if dom in tried:
            continue
        tried.add(dom)
        # dom is derived from an attacker-controlled PTR record and flows into a
        # shell command + an output path. A real DNS zone name is only
        # [a-z0-9.-]; anything else is noise or a shell-injection attempt (e.g. a
        # PTR of "a.$(id).com"), so skip it rather than feed it to the shell.
        # shlex.quote below is belt-and-suspenders on top of this validation.
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", dom):
            continue
        rc3, out3 = await runner.run(
            f"dig @{host} -p {port} {shlex.quote(dom)} axfr +time=10 +tries=1",
            f"{tag}/axfr_{dom}.txt", "dig-axfr", timeout=30)
        if out3 and "XFR size:" in out3:
            findings.append(Finding("CRITICAL", "dns", port,
                f"DNS zone transfer (AXFR) succeeded for '{dom}' - full zone dumped, "
                f"see {tag}/axfr_{dom}.txt"))

    if tried:
        good(f"dns checks done (AXFR tried against: {', '.join(sorted(tried))})")
    else:
        good("dns basic checks done (no domain known yet to try AXFR against - "
             "pass -d/--domain, or add AXFR manually once you know the domain)")


async def enum_nfs(host, runner, args, findings):
    tag = f"{host}/nfs"
    if TOOLS.get("showmount"):
        rc, out = await runner.run(f"showmount -e {host}", f"{tag}/exports.txt", "showmount")
        if out and "*" in out:
            findings.append(Finding("HIGH", "nfs", 2049, "NFS export world-readable (*) - mount it"))
        scan_findings(out, "nfs", 2049, findings)
    nxc = nxc_bin()
    if nxc:
        # nxc enumerates exports with UID/GID and recursive listing - richer
        # than showmount, and works when showmount is absent.
        await _nxc_enum(nxc, "nfs", host, runner, findings, 2049,
                        ("--shares",), tag, prefix="nxc")
    good("nfs enum done")


async def enum_mssql(host, port, runner, args, findings):
    nxc = nxc_bin()
    tag = f"{host}/mssql_{port}"
    if nxc and have_creds(args):
        ok = await _nxc_authed_check(nxc, "mssql", host, port, runner, findings, args,
            f"{tag}/auth_nxc.txt", "nxc-mssql-auth", extra="-x whoami",
            success=Finding("CRITICAL", "mssql", port,
                "MSSQL login works - enable xp_cmdshell for RCE (nxc mssql ... -x whoami / mssqlclient.py)"))
        if ok:
            # Full mode: version query, RID brute, and SAM/LSA dump over MSSQL.
            auth = nxc_auth(args)
            await _nxc_enum(nxc, "mssql", host, runner, findings, port,
                            ('--query "SELECT @@version"', "--rid-brute",
                             "--sam", "--lsa"), tag, auth=auth, prefix="auth_nxc")
    elif nxc:
        rc, out = await runner.run(f"{nxc} mssql {host} -u sa -p '' --local-auth",
                                   f"{tag}/nxc.txt", "nxc-mssql")
        scan_findings(out, "mssql", port, findings)
    findings.append(Finding("MEDIUM", "mssql", port, "MSSQL exposed - test sa/blank and weak creds (impacket mssqlclient)"))


async def enum_redis(host, port, runner, args, findings):
    tag = f"{host}/redis_{port}"
    if TOOLS.get("redis-cli"):
        rc, out = await runner.run(f"redis-cli -h {host} -p {port} INFO",
                                   f"{tag}/info.txt", "redis-info", timeout=30)
        if out and "redis_version" in out:
            findings.append(Finding("HIGH", "redis", port, "Redis reachable without auth - INFO succeeded"))


async def enum_postgres(host, port, runner, args, findings):
    tag = f"{host}/postgres_{port}"
    nxc = nxc_bin()
    # 1) nmap pgsql-brute: only as a fallback when nxc isn't around to do the
    # same job faster. It brute-forces with nmap's full default word lists,
    # so cap it with --script-timeout rather than letting it run to the enum
    # timeout - it's opportunistic, not meant to complete.
    if TOOLS.get("nmap") and not nxc:
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script pgsql-brute --script-timeout 20s -oN /dev/stdout {host}",
            f"{tag}/pgsql_nse.txt", "nmap-pgsql", timeout=45)
        scan_findings(out, "postgres", port, findings)
    # 2) netexec: use supplied creds if we have them, else default-cred sweep
    if nxc and have_creds(args):
        rc, out = await runner.run(f"{nxc} postgres {host} {nxc_auth(args)}",
                                   f"{tag}/auth_nxc.txt", f"{nxc}-postgres-auth")
        scan_findings(out, "postgres", port, findings)
    elif nxc:
        for user, pw in (("postgres", "postgres"), ("postgres", ""), ("postgres", "password")):
            rc, out = await runner.run(
                f"{nxc} postgres {host} -u {user} -p '{pw}'",
                f"{tag}/nxc_{user}_{pw or 'blank'}.txt", f"{nxc}-postgres")
            scan_findings(out, "postgres", port, findings)
    # 3) direct psql connectivity probe (no password) if the client is present
    if TOOLS.get("psql"):
        cmd = (f"PGPASSWORD='' psql 'host={host} port={port} user=postgres "
               f"dbname=postgres connect_timeout=8' -c '\\l' ")
        rc, out = await runner.run(cmd, f"{tag}/psql_list.txt", "psql-list", timeout=60)
        if out and ("List of databases" in out or "template1" in out):
            findings.append(Finding("CRITICAL", "postgres", port,
                                    "PostgreSQL blank-password login as 'postgres' works - dumped DB list"))
        scan_findings(out, "postgres", port, findings)
    if not (TOOLS.get("nxc") or TOOLS.get("netexec") or TOOLS.get("psql")):
        findings.append(Finding("MEDIUM", "postgres", port,
                                "PostgreSQL open - install netexec/psql, then test postgres:postgres & blank"))
    good("postgres enum done")


async def enum_mysql(host, port, runner, args, findings):
    """MySQL / MariaDB (3306). netexec has no reliable 'mysql' protocol (many
    builds omit it - it errors 'invalid choice'), so enumeration is via nmap NSE
    + the mysql/mariadb client: version/info, an empty-password check, and a
    small default-cred probe. Surfaces the common ERROR 1130 host-restriction so
    you know to retry from an allowed host once you have a foothold."""
    tag = f"{host}/mysql_{port}"
    result = None   # 'access' (got in) | 'restricted' (1130) | 'up' (reachable)

    # 1) nmap NSE: server info + empty-password check.
    if TOOLS.get("nmap"):
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script mysql-info,mysql-empty-password "
            f"--script-timeout 30s -oN /dev/stdout {host}",
            f"{tag}/mysql_nse.txt", "nmap-mysql", timeout=70)
        scan_findings(out, "mysql", port, findings)
        if out and re.search(r"MySQL|MariaDB|mysql-info", out, re.I):
            result = "up"

    # 2) direct client probe: small default-cred sweep (like enum_postgres, these
    # are DB-local defaults, not the domain credential).
    myclient = _first_tool("mysql", "mariadb")
    if myclient:
        for user, pw in (("root", ""), ("root", "root"), ("root", "password")):
            cmd = (f"{myclient} -h {host} -P {port} -u {shlex.quote(user)} "
                   f"--password={shlex.quote(pw)} --connect-timeout=8 -e 'show databases;'")
            rc, out = await runner.run(cmd, f"{tag}/client_{user}_{pw or 'blank'}.txt",
                                       "mysql-client", timeout=30)
            low = (out or "").lower()
            if "information_schema" in low:
                findings.append(Finding("CRITICAL", "mysql", port,
                    f"MySQL default creds work (root:{pw or '<blank>'}) - dumped database list"))
                result = "access"
                break
            if "not allowed to connect" in low or "error 1130" in low:
                findings.append(Finding("MEDIUM", "mysql", port,
                    "MySQL/MariaDB reachable but host-restricted (ERROR 1130) - "
                    "retry from an allowed host after a foothold"))
                result = "restricted"
                break
            if "access denied" in low:
                result = "up"   # service up, default creds rejected

    if result == "up":
        findings.append(Finding("MEDIUM", "mysql", port,
            "MySQL/MariaDB reachable - test weak/default creds; reuse app/config creds found elsewhere"))
    elif result is None and not (TOOLS.get("nmap") or myclient):
        findings.append(Finding("MEDIUM", "mysql", port,
            "MySQL open - install nmap or a mysql/mariadb client to enumerate"))
    good("mysql enum done")


async def _mail_probe(host, port, tls, runner, tag, label, payload="CAPA\\r\\nQUIT\\r\\n"):
    """Send a raw payload and grab the response. Uses openssl for TLS ports,
    ncat/nc otherwise. Default payload is POP3/generic CAPA+QUIT; callers on
    a protocol that needs tagged commands (e.g. IMAP's 'a1 CAPABILITY') pass
    their own."""
    if tls and TOOLS.get("openssl"):
        cmd = (f"printf '{payload}' | timeout 15 "
               f"openssl s_client -quiet -connect {host}:{port} 2>/dev/null")
    elif TOOLS.get("ncat"):
        cmd = f"printf '{payload}' | ncat --recv-only -w 10 {host} {port}"
    elif TOOLS.get("nc"):
        cmd = f"printf '{payload}' | nc -w 10 {host} {port}"
    else:
        cmd = None
    if cmd:
        rc, out = await runner.run(cmd, f"{tag}/{label}_banner.txt", label, timeout=30)
        return out or ""
    return ""


async def enum_pop3(host, port, runner, args, findings):
    tag = f"{host}/pop3_{port}"
    tls = port in (995,)
    if TOOLS.get("nmap"):
        await _nmap_nse(host, port, "pop3-capabilities,pop3-ntlm-info", "pop3", runner, tag, findings)
    banner = await _mail_probe(host, port, tls, runner, tag, "pop3")
    # POP3 CAPA speaks USER/SASL; craft the finding from what we saw
    scan_findings(banner, "pop3", port, findings)
    if banner and ("USER" in banner.upper() or "+OK" in banner):
        findings.append(Finding("HIGH", "pop3", port,
                                "POP3 accepts USER/PASS - reuse creds harvested elsewhere (mail often = domain creds)"))
    good("pop3 enum done")


async def enum_imap(host, port, runner, args, findings):
    tag = f"{host}/imap_{port}"
    tls = port in (993,)
    if TOOLS.get("nmap"):
        await _nmap_nse(host, port, "imap-capabilities,imap-ntlm-info", "imap", runner, tag, findings)
    # IMAP CAPABILITY needs a tagged command, unlike POP3's plain CAPA
    banner = await _mail_probe(host, port, tls, runner, tag, "imap",
                               payload="a1 CAPABILITY\\r\\na2 LOGOUT\\r\\n")
    scan_findings(banner, "imap", port, findings)
    if banner and ("CAPABILITY" in banner.upper() or "* OK" in banner):
        findings.append(Finding("HIGH", "imap", port,
                                "IMAP LOGIN available - reuse creds harvested elsewhere"))
    good("imap enum done")


async def enum_winrm(host, port, runner, args, findings):
    tag = f"{host}/winrm_{port}"
    if have_creds(args):
        nxc = nxc_bin()
        if nxc:
            pw = "-H <hash>" if getattr(args, "hash", None) else "-p <pass>"
            ok = await _nxc_authed_check(nxc, "winrm", host, port, runner, findings, args,
                f"{tag}/auth_nxc.txt", "nxc-winrm-auth",
                success=Finding("CRITICAL", "winrm", port,
                    f"WinRM login works -> SHELL: evil-winrm -i {host} -u {args.user} {pw}"),
                on_fail=Finding("INFO", "winrm", port,
                    "WinRM open - supplied credential did not confirm a login (see auth_nxc.txt)"))
            if ok:
                # Full mode: dump creds over WinRM and prove command execution.
                auth = nxc_auth(args)
                await _nxc_enum(nxc, "winrm", host, runner, findings, port,
                                ("--sam", "--lsa", "--dpapi", "--laps"),
                                tag, auth=auth, prefix="auth_nxc")
                rc, out = await runner.run(f"{nxc} winrm {host} {auth} -x whoami",
                                           f"{tag}/auth_nxc_exec_whoami.txt",
                                           f"{nxc} winrm -x whoami")
                scan_findings(out, "winrm", port, findings)
        else:
            findings.append(Finding("MEDIUM", "winrm", port,
                "WinRM open - creds supplied but netexec/nxc not found, credential untested here"))
        return
    # No creds: still run an unauthenticated nxc banner grab - it leaks the
    # hostname / domain / OS build even without a login, which seeds AD recon.
    nxc = nxc_bin()
    if nxc:
        rc, out = await runner.run(f"{nxc} winrm {host}",
                                   f"{tag}/nxc.txt", "nxc-winrm")
        scan_findings(out, "winrm", port, findings)
    findings.append(Finding("MEDIUM", "winrm", port,
                            "WinRM open - if you get creds, use evil-winrm for a shell"))


async def enum_rdp(host, port, runner, args, findings):
    tag = f"{host}/rdp_{port}"
    if TOOLS.get("nmap"):
        out = await _nmap_nse(host, port, "rdp-ntlm-info,rdp-enum-encryption", "rdp",
                              runner, tag, findings)
        m = re.search(r"(DNS_Domain_Name|Target_Name|NetBIOS_Domain_Name):\s*(\S+)", out or "")
        if m:
            findings.append(Finding("MEDIUM", "rdp", port, f"RDP NTLM info leaks: {m.group(2)}"))
    nxc = nxc_bin()
    if have_creds(args):
        if nxc:
            await _nxc_authed_check(nxc, "rdp", host, port, runner, findings, args,
                f"{tag}/auth_nxc.txt", "nxc-rdp-auth",
                success=Finding("HIGH", "rdp", port,
                    f"RDP login works: xfreerdp /u:{args.user} /p:<pass> /v:{host} /cert:ignore"))
    elif nxc:
        # No creds: unauthenticated nxc banner grab - hostname / domain / OS
        # build and NLA status, complementing the nmap NTLM-info NSE above.
        rc, out = await runner.run(f"{nxc} rdp {host}",
                                   f"{tag}/nxc.txt", "nxc-rdp")
        scan_findings(out, "rdp", port, findings)


async def enum_vnc(host, port, runner, args, findings):
    """VNC (5900+). netexec detects no-auth VNC and validates a supplied
    password; screenshots are intentionally skipped (display-dependent)."""
    tag = f"{host}/vnc_{port}"
    nxc = nxc_bin()
    if not nxc:
        findings.append(Finding("MEDIUM", "vnc", port,
            "VNC open - install netexec, or connect with vncviewer to check for no-auth"))
        return
    auth = f"-p {shlex.quote(args.password)}" if getattr(args, "password", None) else ""
    rc, out = await runner.run(f"{nxc} vnc {host} --port {port} {auth}".strip(),
                               f"{tag}/nxc.txt", f"{nxc} vnc")
    scan_findings(out, "vnc", port, findings)
    if _nxc_login_ok(out):
        findings.append(Finding("CRITICAL", "vnc", port,
            f"VNC accessible (no/weak auth) - vncviewer {host}::{port}"))
    else:
        findings.append(Finding("MEDIUM", "vnc", port,
            "VNC open - test blank/weak password (vncviewer), check for CVE-2006-2369-style bypass"))
    good("vnc enum done")


_WMI_DONE = set()


async def enum_wmi(host, port, runner, args, findings):
    """WMI / MSRPC (135). With creds, netexec's wmi protocol is an alternate
    command-execution path when SMB exec (445) is blocked or non-admin.

    nxc wmi targets the host (via the 135 endpoint mapper), not a port, so this
    runs once per host - the guard stops a box with several RPC ports open from
    re-running the identical check. (Cooperative asyncio: the check+add below is
    race-free with no await between them, matching the _SNMP_DONE guard.)"""
    if host in _WMI_DONE:
        return
    _WMI_DONE.add(host)
    nxc = nxc_bin()
    if not (nxc and have_creds(args)):
        findings.append(Finding("INFO", "wmi", port,
            "MSRPC/WMI (135) open - with creds, try 'nxc wmi <host> -u .. -p ..' "
            "(alt exec path) and impacket rpcdump/wmiexec"))
        return
    auth = nxc_auth(args)
    ok = await _nxc_authed_check(nxc, "wmi", host, port, runner, findings, args,
        f"{host}/wmi/auth_nxc.txt", "nxc-wmi-auth",
        success=Finding("HIGH", "wmi", port,
            f"WMI auth works: {nxc} wmi {host} {cred_label(args)} -x whoami (alt to SMB exec)"))
    if ok:
        # Full mode: prove command execution over WMI/DCOM.
        rc, out = await runner.run(f"{nxc} wmi {host} {auth} -x whoami",
                                   f"{host}/wmi/auth_nxc_exec_whoami.txt", f"{nxc} wmi -x whoami")
        scan_findings(out, "wmi", port, findings)
    good("wmi enum done")


# --------------------------------------------------------------------------- #
#  Web content enumeration (background) - the OSCP dir-bust, automated
# --------------------------------------------------------------------------- #
_WEB_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]
def _web_wordlist():
    return _first_existing_file(_WEB_WORDLISTS)


# DNS/vhost name lists for virtual-host fuzzing (--web). Smaller than the dir
# lists on purpose: vhost fuzzing fires one request per name against the live
# host, so a 5k list is the right order of magnitude for an exam box.
_VHOST_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/namelist.txt",
    "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
    "/usr/share/wordlists/dnsmap.txt",
]
def _vhost_wordlist():
    return _first_existing_file(_VHOST_WORDLISTS)


def _is_ipv4(s):
    """True for a dotted-quad like 10.129.58.62 (so we don't try to fuzz
    FUZZ.<ip>, which is meaningless)."""
    parts = (s or "").split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _registrable_domain(hostname):
    """Reduce a hostname to the base domain we append FUZZ. to: the last two
    labels (ghostlink.htb, www.ghostlink.htb -> ghostlink.htb). Returns None
    for an IP or a single-label/empty name. Good enough for lab TLDs
    (.htb/.local/.thm/...); multi-part public suffixes like co.uk aren't a
    concern on exam/lab targets and are documented as a known limitation."""
    if not hostname or _is_ipv4(hostname):
        return None
    labels = [l for l in hostname.strip().strip(".").lower().split(".") if l]
    if len(labels) < 2:
        return None
    return ".".join(labels[-2:])


_VHOST_REDIRECT_RX = re.compile(r"^location:\s*https?://([A-Za-z0-9.-]+)", re.I | re.M)


def _vhost_base_domain(host, args, root_out):
    """Pick the domain to vhost-fuzz, in priority order:
      1. an explicit -d/--domain,
      2. the target itself when it's a hostname (reconx ghostlink.htb),
      3. a hostname from the root page's redirect Location (the common HTB
         'IP 302s to ghostlink.htb' lead).
    Returns (domain, redirect_host_or_None); domain is None if nothing usable
    resolves (e.g. a bare-IP target that doesn't redirect to a name)."""
    for cand in (getattr(args, "domain", None), host):
        dom = _registrable_domain(cand)
        if dom:
            return dom, None
    m = _VHOST_REDIRECT_RX.search(root_out or "")
    if m and not _is_ipv4(m.group(1)):
        return _registrable_domain(m.group(1)), m.group(1)
    return None, None


def _parse_ffuf_vhosts(text, domain, limit=25):
    """ffuf -s prints just the matched FUZZ keyword, one per line (nothing
    else), so each clean label becomes <label>.<domain>. Version-stable and
    free of JSON input-encoding quirks."""
    out, seen = [], set()
    for line in (text or "").splitlines():
        label = line.strip()
        if label and re.fullmatch(r"[A-Za-z0-9_-]+", label) and label not in seen:
            seen.add(label)
            out.append(f"{label}.{domain}")
            if len(out) >= limit:
                break
    return out


def _parse_gobuster_vhosts(text, limit=25):
    """gobuster vhost prints 'Found: name.domain Status: 200 [Size: N]'."""
    out, seen = [], set()
    for line in (text or "").splitlines():
        m = re.search(r"Found:\s*([A-Za-z0-9._-]+)", line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            out.append(m.group(1))
            if len(out) >= limit:
                break
    return out


# vhost fuzzing is per-host, not per-web-port: this guards against the N web
# ports on one host each kicking off a (slow) fuzz. asyncio is cooperative, so
# the check+add below is race-free as long as nothing awaits between them.
_VHOST_FUZZED = set()


async def enum_vhosts(host, port, scheme, url, runner, args, findings, root_out, cap):
    """Virtual-host discovery for the --web deep pass. Resolves a base domain,
    then fuzzes Host: FUZZ.<domain> with ffuf -ac (auto-calibrated, so the
    default/wildcard response is filtered) or gobuster vhost. Each hit is a
    HIGH finding naming the vhost to add to /etc/hosts. Runs at most once per
    host; degrades to a single INFO when it can't run."""
    if host in _VHOST_FUZZED:
        return
    _VHOST_FUZZED.add(host)

    domain, redirect_host = _vhost_base_domain(host, args, root_out)
    if redirect_host:
        findings.append(Finding("HIGH", "http", port,
            f"Root redirects to '{redirect_host}' - add '{host} {redirect_host}' to "
            f"/etc/hosts and re-browse (name-based vhost)"))
    if not domain:
        findings.append(Finding("INFO", "http", port,
            f"vhost fuzz skipped on {url} - no base domain; pass -d <domain> "
            f"(or add a discovered vhost to /etc/hosts) and re-run --web"))
        return

    wl = _vhost_wordlist()
    if not wl:
        findings.append(Finding("INFO", "http", port,
            f"vhost fuzz skipped - no DNS wordlist found (seclists subdomains-top1million-*); "
            f"install seclists or fuzz Host: FUZZ.{domain} manually"))
        return

    vhosts = []
    if TOOLS.get("ffuf"):
        # -ac auto-calibrates against the base response so unknown vhosts (which
        # return the default page) are filtered; -s prints only matched labels.
        cmd = (f"ffuf -u {scheme}://{host}:{port}/ -H {shlex.quote('Host: FUZZ.' + domain)} "
               f"-w {shlex.quote(wl)} -t 40 -k -ac -s -maxtime {cap}")
        rc, out = await runner.run(cmd, f"{host}/web_{port}/ffuf_vhost.txt",
                                   "ffuf-vhost", timeout=cap + 30)
        vhosts = _parse_ffuf_vhosts(out, domain)
    elif TOOLS.get("gobuster"):
        cmd = (f"gobuster vhost -u {scheme}://{host}:{port} --domain {shlex.quote(domain)} "
               f"--append-domain -w {shlex.quote(wl)} -q -k -t 40")
        rc, out = await runner.run(cmd, f"{host}/web_{port}/gobuster_vhost.txt",
                                   "gobuster-vhost", timeout=cap + 30)
        vhosts = _parse_gobuster_vhosts(out)
    else:
        findings.append(Finding("INFO", "http", port,
            f"vhost fuzz skipped - no ffuf/gobuster; fuzz Host: FUZZ.{domain} manually"))
        return

    for vh in vhosts:
        findings.append(Finding("HIGH", "http", port,
            f"virtual host: {vh} - add '{host} {vh}' to /etc/hosts and browse {scheme}://{vh}:{port}"))
    if not vhosts:
        findings.append(Finding("INFO", "http", port,
            f"vhost fuzz on {domain} found nothing new (auto-calibrated) - try a larger DNS list"))

# high-value paths worth pulling straight into the ranked findings
_WEB_JUICY = re.compile(
    r"(\.git|\.svn|\.env|\.htpasswd|/backup|\.bak|\.old|\.sql|/upload|"
    r"phpmyadmin|wp-admin|wp-login|/admin|/manager|/console|/actuator|swagger|"
    r"\.zip|\.tar|id_rsa|/api/|/config|/setup|/install|/dashboard)", re.I)

_HTTPS_PORTS = {443, 8443, 9443, 8834, 4443}


def _web_scheme(port, name):
    n = (name or "").lower()
    if port in _HTTPS_PORTS or "https" in n or "ssl" in n:
        return "https"
    return "http"


def _ffuf_json_to_lines(text):
    """Convert ffuf JSON (-of json) into feroxbuster-style 'STATUS GET URL'
    lines so the existing _web_paths_to_findings parser handles ffuf output the
    same way it handles feroxbuster/gobuster - no second parser to keep in sync.
    Tolerant of malformed/empty input (returns '')."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return ""
    lines = []
    for r in (data.get("results") or []):
        url = r.get("url") or ""
        status = r.get("status")
        if url and status:
            lines.append(f"{status} GET {url}")
    return "\n".join(lines)


def _web_paths_to_findings(text, host, port, findings, limit=12):
    """Parse feroxbuster/gobuster output; surface juicy paths as HIGH, and a
    one-line INFO count of everything else, so notes don't drown in 200s."""
    hits = []   # (status, url_or_path)
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d{3})\s+\w+\s+.*?(https?://\S+|/\S*)\s*$", line)
        if m:
            hits.append((m.group(1), m.group(2))); continue
        m = re.match(r"^(/\S*)\s+\(Status:\s*(\d{3})\)", line)  # gobuster
        if m:
            hits.append((m.group(2), m.group(1)))
    juicy, count = [], 0
    seen = set()
    for status, path in hits:
        if path in seen:
            continue
        seen.add(path); count += 1
        if _WEB_JUICY.search(path) and len(juicy) < limit:
            juicy.append((status, path))
    for status, path in juicy:
        findings.append(Finding("HIGH", "http", port,
            f"web path [{status}] {path} - inspect (auth/upload/leak/source)"))
    if count:
        findings.append(Finding("INFO", "http", port,
            f"dir brute found {count} path(s) on port {port} - see web_{port}/ output"))


async def enum_http(host, port, runner, args, findings):
    """Default: a fast whatweb fingerprint + root grab only - the slow directory
    brute is deliberately NOT part of an initial scan (it dominated the runtime).
    Under --web the deep pass adds a bounded directory brute (feroxbuster, else
    gobuster) + nikto. Skip everything with --no-web."""
    if getattr(args, "no_web", False):
        return
    deep = getattr(args, "web", False)
    scheme = _web_scheme(port, "")
    tag = f"{host}/web_{port}"
    url = f"{scheme}://{host}:{port}"

    # Fingerprint - always cheap, runs in both the initial scan and --web.
    if TOOLS.get("whatweb"):
        rc, out = await runner.run(
            f"whatweb -a 3 --no-errors --color=never {url}",
            f"{tag}/whatweb.txt", "whatweb", timeout=60)
        scan_findings(out, "http", port, findings)
        m = re.search(r"Title\[([^\]]+)\]", out or "")
        if m:
            findings.append(Finding("INFO", "http", port, f"Web title: {m.group(1).strip()[:80]}"))
    root_out = ""
    if TOOLS.get("curl"):
        rc, out = await runner.run(
            f"curl -sSik --max-time 15 {url}/", f"{tag}/curl_root.txt", "curl-root", timeout=25)
        root_out = out or ""
        scan_findings(out, "http", port, findings)

    if not deep:
        # Initial scan stays fast: fingerprint only. Point the user at --web for
        # the heavy content-discovery pass rather than paying for it every scan.
        findings.append(Finding("INFO", "http", port,
            f"Web on {url} - fingerprint only; run 'reconx {host} --web' for dir-brute + nikto"))
        good(f"web fingerprint ({url}) done")
        return

    # --web deep pass: directory brute (feroxbuster > gobuster) + nikto.
    wl = _web_wordlist()
    cap = min(getattr(args, "web_timeout", 180) or 180, getattr(args, "enum_timeout", 600))
    if wl and TOOLS.get("feroxbuster"):
        cmd = (f"feroxbuster -u {url} -w {shlex.quote(wl)} -t 50 -q -k -n "
               f"-s 200,204,301,302,307,401,403 --time-limit {cap}s --no-state")
        rc, out = await runner.run(cmd, f"{tag}/feroxbuster.txt", "feroxbuster", timeout=cap + 30)
        _web_paths_to_findings(out, host, port, findings)
    elif wl and TOOLS.get("gobuster"):
        cmd = (f"gobuster dir -u {url} -w {shlex.quote(wl)} -q -k -t 50 --no-error")
        rc, out = await runner.run(cmd, f"{tag}/gobuster.txt", "gobuster", timeout=cap + 30)
        _web_paths_to_findings(out, host, port, findings)
    elif wl and TOOLS.get("ffuf"):
        # ffuf has no feroxbuster/gobuster-style stdout, so write JSON and parse
        # that via _ffuf_json_to_lines. Path mirrors Runner.run's outfile mapping
        # (flat mode strips the leading host segment) so it lands beside the
        # other web output. In --dry-run no file is written -> the read just
        # no-ops, consistent with dry-run emitting no findings.
        rel = f"{tag}/ffuf.json"
        if runner.flat and "/" in rel:
            rel = rel.split("/", 1)[1]
        jpath = os.path.join(runner.outdir, rel)
        cmd = (f"ffuf -u {url}/FUZZ -w {shlex.quote(wl)} -t 50 -k -s "
               f"-mc 200,204,301,302,307,401,403 -of json -o {shlex.quote(jpath)}")
        await runner.run(cmd, f"{tag}/ffuf_stdout.txt", "ffuf", timeout=cap + 30)
        try:
            with open(jpath, errors="replace") as fh:
                _web_paths_to_findings(_ffuf_json_to_lines(fh.read()), host, port, findings)
        except OSError:
            pass
    else:
        findings.append(Finding("INFO", "http", port,
            f"Web on {url} - no feroxbuster/gobuster/ffuf+wordlist found; run your own dir brute"))
    if TOOLS.get("nikto"):
        rc, out = await runner.run(
            f"nikto -h {url} -maxtime {cap}s -ask no -nointeractive",
            f"{tag}/nikto.txt", "nikto", timeout=cap + 30)
        scan_findings(out, "http", port, findings)
    # virtual-host discovery (once per host; see enum_vhosts) - a web box often
    # gates its real app behind a name-based vhost that must be in /etc/hosts.
    await enum_vhosts(host, port, scheme, url, runner, args, findings, root_out, cap)
    good(f"web enum ({url}) done")


# --------------------------------------------------------------------------- #
#  Host-type-aware enum priority
#
#  Not in this table -> "unknown" host type -> every module falls back to
#  flat PRIO_ENUM, i.e. today's behavior when classification can't say
#  anything useful. A host-type entry only needs to list what it wants to
#  pull FORWARD (PRIO_ENUM_HIGH) or push BACK (PRIO_ENUM_LOW) relative to
#  that same default - this is a soft preference, not a hard gate: a
#  LOW-priority module still runs on any worker that would otherwise sit
#  idle, it just always loses the tie-break to a HIGH one.
# --------------------------------------------------------------------------- #
_HOST_TYPE_ENUM_PRIORITY = {
    "ad": {"smb": PRIO_ENUM_HIGH, "ldap": PRIO_ENUM_HIGH, "dns": PRIO_ENUM_HIGH,
           "winrm": PRIO_ENUM_HIGH, "web": PRIO_ENUM_LOW, "ftp": PRIO_ENUM_LOW,
           "ssh": PRIO_ENUM_LOW},
    "windows": {"smb": PRIO_ENUM_HIGH, "winrm": PRIO_ENUM_HIGH, "rdp": PRIO_ENUM_HIGH,
                "web": PRIO_ENUM_LOW},
    "linux": {"ssh": PRIO_ENUM_HIGH, "web": PRIO_ENUM_LOW, "mssql": PRIO_ENUM_LOW, "mysql": PRIO_ENUM_LOW},
    "web": {"web": PRIO_ENUM_HIGH},
}


def _service_priority(module_key, host_type):
    return _HOST_TYPE_ENUM_PRIORITY.get(host_type, {}).get(module_key, PRIO_ENUM)


# --------------------------------------------------------------------------- #
#  Dispatcher: map discovered services -> queued jobs
#
#  Pure and idempotent: called TWICE per host - once right after port
#  discovery with port-guessed service names (so enum starts within
#  seconds, not after the full nmap -sCV pass across every port), and again
#  once service_scan() confirms real versions. Job ids are deterministic, so
#  a job the guess pass already registered is a harmless dedup no-op on the
#  confirm pass (except for priority - see JobQueue.add_job's decrease-key
#  handling: the confirm pass's better host-type classification can still
#  reprioritize a job the guess pass already queued, as long as it hasn't
#  started yet); a job the guess pass missed (nmap corrects a wrong guess)
#  still fires from the confirm pass, just later, without blocking anything.
# --------------------------------------------------------------------------- #
# Ports the --ad pass enumerates: SMB, Kerberos, kpasswd, RPC, LDAP (incl.
# Global Catalog), and WinRM - the DC-facing surface. Deliberately distinct
# from the narrower _AD_PORTS discriminator set (see top of file) that
# classify_host_type uses to *decide* a host is a DC: this one drives the --ad
# module filter and the quick DC-port probe when no cached ports exist yet.
_AD_SURFACE_PORTS = {53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 5985, 5986}
# Service-name substrings that mark an AD-relevant port even on a non-standard
# number, so --ad's port-number filter doesn't miss e.g. LDAP on an odd port.
_AD_NAME_HINTS = ("microsoft-ds", "netbios", "ldap", "kerberos", "msrpc",
                  "epmap", "winrm", "wsman", "domain", "dns")


def _is_ad_port(port, name):
    return port in _AD_SURFACE_PORTS or any(h in name for h in _AD_NAME_HINTS)


async def _ad_port_probe(host, runner, args):
    """Quick connect-sweep of just the DC-facing ports, used by --ad when there's
    no cached port list to reuse. Bounded to _AD_SURFACE_PORTS so it's seconds,
    not a full range scan - the whole point of --ad is a fast re-enum after creds."""
    if runner.dry_run:
        return sorted(_AD_SURFACE_PORTS)
    return await async_port_scan(host, sorted(_AD_SURFACE_PORTS),
                                 concurrency=min(args.concurrency, len(_AD_SURFACE_PORTS)),
                                 timeout=args.host_timeout)


async def _web_port_probe(host, runner, args):
    """Quick connect-sweep of just the common web ports (WEB_PORTS), used by
    --web when there's no cached port list to reuse. Bounded so it's seconds."""
    if runner.dry_run:
        return sorted(WEB_PORTS)
    return await async_port_scan(host, sorted(WEB_PORTS),
                                 concurrency=min(args.concurrency, len(WEB_PORTS)),
                                 timeout=args.host_timeout)


def register_service_jobs(queue, host, services, runner, args, findings, host_profile):
    counted = host_profile.setdefault("_counted_ports", set())
    host_type = host_profile["host_type"] = classify_host_type(list(services), services)
    ad_only = getattr(args, "ad", False)
    web_only = getattr(args, "web", False)

    def prio(module_key):
        return _service_priority(module_key, host_type)

    for port, meta in sorted(services.items()):
        name = meta.get("name", guess_service(port))

        # --ad: only enumerate the DC-facing surface; skip FTP/SSH/HTTP/DB/etc.
        # entirely (this also skips the web block and profile hints below).
        if ad_only and not _is_ad_port(port, name):
            continue
        # --web: only enumerate web ports; skip every non-web module + profile hints.
        if web_only and not is_web(port, name):
            continue

        if web_only:
            pass  # skip the service dispatch below; fall through to the web block
        elif port in (139, 445) or "microsoft-ds" in name or "netbios" in name:
            queue.add_job(Job(f"{host}:smb", prio("smb"), background=False,
                coro_factory=functools.partial(enum_smb, host, runner, args, findings)))
        elif port in (389, 636, 3268, 3269) or "ldap" in name:
            queue.add_job(Job(f"{host}:ldap", prio("ldap"), background=False,
                coro_factory=functools.partial(enum_ldap, host, port, runner, args, findings, queue)))
        elif port == 21 or "ftp" in name:
            queue.add_job(Job(f"{host}:ftp:{port}", prio("ftp"), background=False,
                coro_factory=functools.partial(enum_ftp, host, port, runner, args, findings)))
        elif port == 22 or "ssh" in name:
            queue.add_job(Job(f"{host}:ssh:{port}", prio("ssh"), background=False,
                coro_factory=functools.partial(enum_ssh, host, port, runner, args, findings)))
        elif port == 25 or port in (465, 587) or "smtp" in name:
            queue.add_job(Job(f"{host}:smtp:{port}", prio("smtp"), background=False,
                coro_factory=functools.partial(enum_smtp, host, port, runner, args, findings)))
        elif port == 53 or "domain" in name or "dns" in name:
            queue.add_job(Job(f"{host}:dns:{port}", prio("dns"), background=False,
                coro_factory=functools.partial(enum_dns, host, port, runner, args, findings)))
        elif port == 2049 or "nfs" in name:
            queue.add_job(Job(f"{host}:nfs", prio("nfs"), background=False,
                coro_factory=functools.partial(enum_nfs, host, runner, args, findings)))
        elif port == 161 or "snmp" in name:
            # 161/tcp is rare (SNMP is usually UDP - the UDP scan triggers the
            # same enum_snmp, deduped by the _SNMP_DONE guard), but when it's
            # open over TCP, enumerate it here too.
            queue.add_job(Job(f"{host}:snmp", prio("snmp"), background=False,
                coro_factory=functools.partial(enum_snmp, host, runner, args, findings)))
        elif port == 1433 or "ms-sql" in name or "mssql" in name:
            queue.add_job(Job(f"{host}:mssql:{port}", prio("mssql"), background=False,
                coro_factory=functools.partial(enum_mssql, host, port, runner, args, findings)))
        elif port == 3306 or "mysql" in name or "mariadb" in name:
            queue.add_job(Job(f"{host}:mysql:{port}", prio("mysql"), background=False,
                coro_factory=functools.partial(enum_mysql, host, port, runner, args, findings)))
        elif port in (6379,) or "redis" in name:
            queue.add_job(Job(f"{host}:redis:{port}", prio("redis"), background=False,
                coro_factory=functools.partial(enum_redis, host, port, runner, args, findings)))
        elif port == 5432 or "postgres" in name:
            queue.add_job(Job(f"{host}:postgres:{port}", prio("postgres"), background=False,
                coro_factory=functools.partial(enum_postgres, host, port, runner, args, findings)))
        elif port in (110, 995) or "pop3" in name:
            queue.add_job(Job(f"{host}:pop3:{port}", prio("pop3"), background=False,
                coro_factory=functools.partial(enum_pop3, host, port, runner, args, findings)))
        elif port in (143, 993) or "imap" in name:
            queue.add_job(Job(f"{host}:imap:{port}", prio("imap"), background=False,
                coro_factory=functools.partial(enum_imap, host, port, runner, args, findings)))
        elif port in (5985, 5986) or "winrm" in name:
            queue.add_job(Job(f"{host}:winrm:{port}", prio("winrm"), background=False,
                coro_factory=functools.partial(enum_winrm, host, port, runner, args, findings)))
        elif port == 3389 or "ms-wbt" in name or "rdp" in name:
            queue.add_job(Job(f"{host}:rdp:{port}", prio("rdp"), background=False,
                coro_factory=functools.partial(enum_rdp, host, port, runner, args, findings)))
        elif port in (5900, 5901, 5902) or "vnc" in name:
            queue.add_job(Job(f"{host}:vnc:{port}", prio("vnc"), background=False,
                coro_factory=functools.partial(enum_vnc, host, port, runner, args, findings)))
        elif port == 135 or (("msrpc" in name or "epmap" in name) and port < 49152):
            # WMI/MSRPC auth goes through the 135 endpoint mapper and nxc wmi
            # targets the host, not a port. Windows exposes dozens of dynamic
            # RPC ports (49152+), all labelled "msrpc" by nmap - dispatching
            # enum_wmi for each just re-runs the identical check and floods the
            # output with duplicate (Pwn3d!) lines. Gate to the epmapper / any
            # static RPC port; _WMI_DONE then makes it one run per host.
            queue.add_job(Job(f"{host}:wmi:{port}", prio("wmi"), background=False,
                coro_factory=functools.partial(enum_wmi, host, port, runner, args, findings)))

        if is_web(port, name) and not getattr(args, "no_web", False):
            # --web: web IS the point, so run it as a core job (the summary waits
            # on it) at high priority. Normal scan keeps it backgrounded so the
            # summary prints first and web results refresh notes when done.
            queue.add_job(Job(f"{host}:web:{port}",
                PRIO_ENUM_HIGH if web_only else PRIO_BACKGROUND,
                background=not web_only,
                coro_factory=functools.partial(enum_http, host, port, runner, args, findings)))

        # profile hints - guarded per-port so the guess pass + confirm pass
        # (both of which see this same port) never double-count.
        if not web_only and port not in counted:
            if port == 88 or "kerberos" in name:
                host_profile["dc_signals"] += 1
                findings.append(Finding("HIGH", "ad", 88, "Kerberos (88) open - strong Domain Controller signal"))
                counted.add(port)
            elif port in (389, 636) and (445 in services or 88 in services):
                host_profile["dc_signals"] += 1
                counted.add(port)


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #
def print_summary(host, services, udp, findings, host_profile, elapsed, args=None):
    print()
    print(f"{C.BOLD}{'='*70}{C.END}")
    print(f"{C.BOLD}  RECONX SUMMARY  -  {host}   ({elapsed:.1f}s){C.END}")
    print(f"{C.BOLD}{'='*70}{C.END}")

    # host profile
    if host_profile["dc_signals"] >= 2:
        print(f"  {C.M}{C.BOLD}HOST PROFILE:{C.END} likely {C.M}Active Directory Domain Controller{C.END} "
              f"- start with LDAP/Kerberos/SMB")
    else:
        label = HOST_TYPE_LABELS.get(host_profile.get("host_type"))
        if label:
            print(f"  {C.M}{C.BOLD}HOST PROFILE:{C.END} likely {C.M}{label}{C.END} - enum priority weighted accordingly")
    print()

    # open ports table
    print(f"  {C.BOLD}OPEN TCP PORTS{C.END}")
    for port in sorted(services):
        meta = services[port]
        ver = meta.get("version", "")
        print(f"    {C.G}{port:<6}{C.END} {meta.get('name',''):<16} {C.DIM}{ver}{C.END}")
    if udp:
        print(f"\n  {C.BOLD}OPEN UDP PORTS{C.END}")
        for port, name in sorted(udp.items()):
            print(f"    {C.CY}{port:<6}{C.END} {name}")
    print()

    # findings, ranked
    if findings:
        # de-dup
        seen = set(); uniq = []
        for f in findings:
            key = (f.sev, f.service, f.port, f.text)
            if key not in seen:
                seen.add(key); uniq.append(f)
        uniq.sort(key=lambda f: (SEV_ORDER.get(f.sev, 9), f.port or 0))

        print(f"  {C.BOLD}RANKED FINDINGS  (look at these first){C.END}")
        for f in uniq:
            col = SEV_COLOR.get(f.sev, "")
            p = f":{f.port}" if f.port else ""
            print(f"    {col}{f.sev:<8}{C.END} {C.DIM}{f.service}{p}{C.END}  {f.text}")
    else:
        print(f"  {C.DIM}No high-signal findings auto-detected. Enumerate the open "
              f"ports manually - the tool only flags the obvious wins.{C.END}")

    # suggested next steps
    print(f"\n  {C.BOLD}SUGGESTED NEXT STEPS{C.END}")
    for step in suggest_next(services, findings, host_profile, args):
        print(f"    {C.B}->{C.END} {step}")
    print(f"{C.BOLD}{'='*70}{C.END}\n")


def suggest_next(services, findings, host_profile, args=None):
    steps = []
    svc_present = {f.service for f in findings}
    ports = set(services)

    if args is not None and have_creds(args):
        steps.append("You have creds: SPRAY them across every host (reconx <cidr> -u .. -p .. --spray) - reuse is the fastest win.")
        if any(re.search(r"\(Pwn3d!\)|login works|SHELL", f.text) for f in findings):
            steps.append("Admin/shell confirmed above - get your shell, then dump SAM/LSASS or hunt for the next credential.")

    if any("/etc/hosts entry" in f.text for f in findings):
        steps.append("Add the SMB-derived /etc/hosts line above BEFORE web/AD enum - vhosts, Kerberos and LDAP referrals all need the real hostname to resolve.")
    if host_profile["dc_signals"] >= 2:
        steps.append("AD: enumerate users via LDAP/RID, then AS-REP roast (impacket GetNPUsers) and Kerberoast.")
    ftp_present = "ftp" in svc_present or any(
        p == 21 or "ftp" in services[p].get("name", "").lower() for p in ports)
    if any(f.service == "ftp" and "Anonymous FTP login allowed" in f.text for f in findings):
        steps.append("FTP: anonymous login CONFIRMED - pull every file, check for creds/config/web-root overlap.")
    elif ftp_present:
        steps.append("FTP: anonymous login was NOT confirmed - try harvested/known creds, note the software+version from the banner, and searchsploit it.")
    if 445 in ports or 139 in ports:
        steps.append("SMB: list shares with null/guest, mount readable ones, grep for passwords & scripts.")
    if any(is_web(p, services[p].get('name','')) for p in ports):
        if getattr(args, "web", False):
            steps.append("Web: dir-brute + nikto ran above (--web) - hit 401/403/interesting paths, check source & default creds.")
        else:
            steps.append("Web: initial scan fingerprinted only - run 'reconx <host> --web' for dir-brute + nikto, then hit 401/403/interesting paths & default creds.")
    if 22 in ports:
        steps.append("SSH: no shell yet - only useful once you harvest a username+password/key elsewhere.")
    if "snmp" in svc_present:
        steps.append("SNMP: full walk with 'public' - extract usernames, running processes, and network info.")
    if 5432 in ports or "postgres" in svc_present:
        steps.append("PostgreSQL: try postgres:postgres/blank; if in, use COPY ... FROM PROGRAM or pg_read_file to read/exec.")
    if 110 in ports or 143 in ports or 993 in ports or 995 in ports or "pop3" in svc_present or "imap" in svc_present:
        steps.append("Mail (POP3/IMAP): try creds you've already harvested - mailbox logins often reuse domain passwords and leak more creds.")
    if not steps:
        steps.append("Re-read raw output under the loot dir; run a full -p- if you only did top-ports.")
    steps.append("Keep a full-range TCP + UDP scan running in the background while you work the above.")
    return steps


def write_markdown(host, services, udp, findings, host_dir, host_profile):
    path = os.path.join(host_dir, "NOTES.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"# recon notes - {host}\n\n_generated {datetime.now():%Y-%m-%d %H:%M}_\n\n")
        if host_profile["dc_signals"] >= 2:
            f.write("> **Host profile:** likely Active Directory Domain Controller.\n\n")
        else:
            label = HOST_TYPE_LABELS.get(host_profile.get("host_type"))
            if label:
                f.write(f"> **Host profile:** likely {label}.\n\n")
        f.write("## Open TCP ports\n\n| Port | Service | Version |\n|---|---|---|\n")
        for p in sorted(services):
            m = services[p]
            f.write(f"| {p} | {m.get('name','')} | {m.get('version','')} |\n")
        if udp:
            f.write("\n## Open UDP ports\n\n| Port | Service |\n|---|---|\n")
            for p in sorted(udp):
                f.write(f"| {p} | {udp[p]} |\n")
        f.write("\n## Ranked findings\n\n")
        uniq = {(x.sev, x.service, x.port, x.text) for x in findings}
        for sev, svc, port, text in sorted(uniq, key=lambda t: SEV_ORDER.get(t[0], 9)):
            f.write(f"- **{sev}** `{svc}{':'+str(port) if port else ''}` - {text}\n")
        f.write("\n## To do\n\n- [ ] \n")
    return path


def _effective_host_type(host_profile):
    if host_profile.get("dc_signals", 0) >= 2:
        return "ad"
    return host_profile.get("host_type")


def _write_notes(host, host_state, findings, host_profile, runner, args):
    """Write per-host notes: the enriched reconx_notes version when the module
    is present (frontmatter + vault wikilinks + suggested next steps), else the
    built-in NOTES.md. Returns the path written."""
    services = host_state["services"]
    udp = host_state["udp"]
    if reconx_notes is not None:
        try:
            steps = suggest_next(services, findings, host_profile, args)
        except Exception:
            steps = None
        try:
            return reconx_notes.enrich_host_notes(
                host, services, udp, findings, host_profile, runner.outdir,
                next_steps=steps, host_dir=runner.hostdir(host))
        except Exception as e:  # never let note-gen kill a scan
            warn(f"enriched notes failed ({e}); falling back to plain NOTES.md")
    return write_markdown(host, services, udp, findings, runner.hostdir(host), host_profile)


def _merge_workspace(host, host_state, findings, host_profile, runner, args):
    """Merge this host's recon into the PakCyberbot per-box notes.md, reusing
    its template in place. No-op unless --workspace is set and reconx_notes is
    present. Best-effort - never crashes a scan."""
    if reconx_notes is None or not getattr(args, "workspace", None):
        return
    notes_path = os.path.join(args.workspace, "notes.md")
    if not os.path.isfile(notes_path):
        warn(f"workspace notes.md not found at {notes_path} - skipping merge "
             f"(run setup_pentest_env first)")
        return
    try:
        steps = suggest_next(host_state["services"], findings, host_profile, args)
    except Exception:
        steps = None
    try:
        reconx_notes.merge_workspace_notes(
            notes_path, host, host_state["services"], host_state["udp"],
            findings, host_profile,
            os.path.abspath(runner.hostdir(host)), next_steps=steps)
        good(f"findings merged into workspace notes: {notes_path}")
    except Exception as e:
        warn(f"workspace notes merge skipped for {host}: {e}")


def _sync_exam(host, host_state, findings, host_profile, runner, args):
    """Feed this host's recon result into the exam dashboard + vault note, if
    an exam is in play. Best-effort and fully optional."""
    if reconx_exam is None:
        return
    name = args.exam or reconx_exam.current_exam_name()
    if not name or not reconx_exam.exam_exists(name):
        return
    ht = _effective_host_type(host_profile)
    try:
        # honour --points/--set on first registration
        if getattr(args, "points", None) is not None or getattr(args, "exam_set", None):
            data = reconx_exam.load_exam(name)
            if data is not None and host not in data["targets"]:
                reconx_exam.add_target(data, host, points=args.points,
                                       os_type=ht, set_name=args.exam_set)
                reconx_exam.save_exam(data)
        data = reconx_exam.sync_from_scan(
            name, host, host_type=ht,
            services=host_state["services"], findings=findings,
            ports=host_state["ports"])
        if data is None:
            return
        good(f"exam '{name}': {host} synced ({ht or 'unknown'}, "
             f"{len(host_state['ports'])} ports)")
        if not getattr(args, "no_vault", False) and reconx_notes is not None \
                and data.get("vault_note"):
            reconx_notes.build_exam_note(data, results_dir=runner.outdir)
    except Exception as e:  # bookkeeping must never crash a scan
        warn(f"exam sync skipped for {host}: {e}")


# --------------------------------------------------------------------------- #
#  Host orchestration
#
#  Each job_* wrapper owns "register whatever comes next" as a side effect of
#  finishing its own await - that's the whole dependency mechanism: a job is
#  only ever added by code that runs after its prerequisite already
#  completed, so every job in the queue is runnable the instant it's added.
#  discover_ports()/service_scan()/udp_scan()/enum_*() themselves are
#  untouched pure workers.
# --------------------------------------------------------------------------- #
async def _job_discover_ad(host, runner, args, queue, findings,
                           host_profile, host_state, state_store):
    """--ad orchestrator: reuse cached ports/services from a prior run (or do a
    quick DC-port probe when there's no cache), then register ONLY the AD suite.
    Deliberately queues no service_scan/udp_scan/vuln_scan job - the whole point
    is a fast, creds-in-hand re-enum of the AD surface, not another full scan."""
    cached_ports = state_store.data.get("ports") if state_store else None
    cached_services = state_store.data.get("services") if state_store else None
    if cached_ports and not runner.dry_run:
        ports = cached_ports
        info(f"--ad: reusing {len(ports)} cached port(s) for {host} "
             f"(from {state_store.path})")
    else:
        if not runner.dry_run:
            info(f"--ad: no cached ports for {host} - quick DC-port probe "
                 f"({len(_AD_SURFACE_PORTS)} ports)")
        ports = await _ad_port_probe(host, runner, args)
        if state_store:
            await state_store.save_ports_services(ports=ports)

    # Prefer cached nmap service names; otherwise guess from the port number
    # (reliable for the fixed AD ports the enum modules key off).
    if cached_services and not runner.dry_run:
        services = {p: cached_services.get(p, {"name": guess_service(p), "version": ""})
                    for p in ports}
    else:
        services = {p: {"name": guess_service(p), "version": ""} for p in ports}
    host_state["ports"] = ports
    host_state["services"] = services

    if not ports:
        warn(f"{host}: no AD-relevant ports open (not a DC? try a full scan first)")
        return ports
    good(f"{host}: {len(ports)} AD port(s): {', '.join(map(str, ports))}")

    register_service_jobs(queue, host, services, runner, args, findings, host_profile)
    return ports


async def _job_discover_web(host, runner, args, queue, findings,
                            host_profile, host_state, state_store):
    """--web orchestrator: reuse cached ports/services (or a quick web-port probe),
    then register ONLY the web modules, running the deep pass (dir-brute + nikto).
    Like _job_discover_ad, queues no service_scan/udp_scan/vuln_scan job."""
    cached_ports = state_store.data.get("ports") if state_store else None
    cached_services = state_store.data.get("services") if state_store else None
    if cached_ports and not runner.dry_run:
        ports = cached_ports
        info(f"--web: reusing {len(ports)} cached port(s) for {host} "
             f"(from {state_store.path})")
    else:
        if not runner.dry_run:
            info(f"--web: no cached ports for {host} - quick web-port probe "
                 f"({len(WEB_PORTS)} ports)")
        ports = await _web_port_probe(host, runner, args)
        if state_store:
            await state_store.save_ports_services(ports=ports)

    if cached_services and not runner.dry_run:
        services = {p: cached_services.get(p, {"name": guess_service(p), "version": ""})
                    for p in ports}
    else:
        services = {p: {"name": guess_service(p), "version": ""} for p in ports}
    host_state["ports"] = ports
    host_state["services"] = services

    web_ports = [p for p in ports if is_web(p, services.get(p, {}).get("name", "") or "")]
    if not web_ports:
        warn(f"{host}: no web ports open (run a full scan first, or --no-web is set?)")
        return ports
    good(f"{host}: {len(web_ports)} web port(s): {', '.join(map(str, web_ports))}")

    register_service_jobs(queue, host, services, runner, args, findings, host_profile)
    return ports


async def job_discover(host, runner, args, queue, findings, host_profile, host_state, state_store):
    if getattr(args, "ad", False):
        return await _job_discover_ad(host, runner, args, queue, findings,
                                      host_profile, host_state, state_store)
    if getattr(args, "web", False):
        return await _job_discover_web(host, runner, args, queue, findings,
                                       host_profile, host_state, state_store)
    if (args.resume and state_store
            and state_store.job_status(f"{host}:discover") == "done"
            and state_store.data.get("ports")):
        ports = state_store.data["ports"]
        info(f"resume: using {len(ports)} cached port(s) for {host}")
    else:
        ports = await discover_ports(host, runner, args)
        if runner.dry_run:
            ports = ports or [21, 22, 80, 445]  # sample so the plan shows modules
        if state_store:
            await state_store.save_ports_services(ports=ports)
    host_state["ports"] = ports

    if not ports:
        warn(f"{host}: no open TCP ports found (host down / filtered / try --no-rustscan)")
        return ports
    # In --dry-run the ports are a fixed sample (no scan ran), so label them as
    # such - otherwise the line reads exactly like a real scan result (F3).
    sample_tag = "  (sample - dry-run, no scan ran)" if runner.dry_run else ""
    good(f"{host}: {len(ports)} open port(s): {', '.join(map(str, ports))}{sample_tag}")

    # guess pass: fast opportunistic modules start now, without waiting on nmap
    guessed = {p: {"name": guess_service(p), "version": ""} for p in ports}
    register_service_jobs(queue, host, guessed, runner, args, findings, host_profile)

    queue.add_job(Job(f"{host}:service_scan", PRIO_SCAN, background=False, always_reenter=True,
        coro_factory=functools.partial(job_service_scan, host, ports, runner, args,
                                        queue, findings, host_profile, host_state, state_store)))
    queue.add_job(Job(f"{host}:udp_scan", PRIO_SCAN, background=True,
        coro_factory=functools.partial(job_udp_scan, host, runner, args, host_state, state_store, findings)))
    if args.mode == "deep" and TOOLS.get("nmap"):
        queue.add_job(Job(f"{host}:vuln_scan", PRIO_BACKGROUND, background=True,
            coro_factory=functools.partial(job_vuln_scan, host, ports, runner, args, findings)))
    return ports


async def job_service_scan(host, ports, runner, args, queue, findings, host_profile, host_state, state_store):
    if (args.resume and state_store
            and state_store.job_status(f"{host}:service_scan") == "done"
            and state_store.data.get("services")):
        services = state_store.data["services"]
        info(f"resume: using cached service scan for {host}")
    else:
        services = await service_scan(host, ports, runner, args)
        if state_store:
            await state_store.save_ports_services(services=services)
    host_state["services"] = services

    # confirm pass: corrects anything the port-guess pass got wrong or missed
    register_service_jobs(queue, host, services, runner, args, findings, host_profile)

    if not args.no_exploit_search:
        queue.add_job(Job(f"{host}:searchsploit", PRIO_EXPLOIT, background=False,
            coro_factory=functools.partial(searchsploit_lookup, host, services, runner, args, findings)))
    return services


async def job_udp_scan(host, runner, args, host_state, state_store, findings=None):
    udp = await udp_scan(host, runner, args)
    host_state["udp"] = udp
    if state_store:
        await state_store.save_ports_services(udp=udp)
    # SNMP is almost always UDP, and the TCP dispatcher never sees it - so the
    # UDP scan is what actually triggers SNMP enumeration (community-string
    # sweep + walk). Run it inline here (deduped per host via _SNMP_DONE) rather
    # than queueing a new job from a background task near queue shutdown.
    if findings is not None and 161 in udp:
        await enum_snmp(host, runner, args, findings)
    return udp


_NMAP_PORT_BLOCK_RX = re.compile(r"^(\d+)/tcp\s+open\b", re.M)


async def job_vuln_scan(host, ports, runner, args, findings):
    """--mode deep only: an extra nmap NSE vuln-category sweep, backgrounded
    since it's slow and purely opportunistic."""
    plist = ",".join(str(p) for p in ports)
    cmd = f"nmap -Pn -sV --script vuln -p {plist} -oN /dev/stdout {host}"
    rc, out = await runner.run(cmd, outfile=f"{host}/scans/nmap_vuln.txt",
                               label="nmap-vuln", timeout=args.scan_timeout)
    # Split into per-port blocks so findings get attributed to their real
    # port instead of a bare port=None duplicate of what service_scan/enum_*
    # already found (the -sV banner text that reappears in this output would
    # otherwise re-trigger the same FINDING_RULES with a different dedup key).
    blocks = list(_NMAP_PORT_BLOCK_RX.finditer(out or ""))
    if not blocks:
        scan_findings(out, "vuln", None, findings)
    else:
        for i, m in enumerate(blocks):
            end = blocks[i + 1].start() if i + 1 < len(blocks) else len(out)
            scan_findings(out[m.start():end], "vuln", int(m.group(1)), findings)
    good(f"{host}: vuln-script scan done")


async def scan_host(host, runner, args):
    t0 = time.time()
    host_profile = {"dc_signals": 0}
    host_state = {"ports": [], "services": {}, "udp": {}}
    os.makedirs(os.path.join(runner.hostdir(host), "scans"), exist_ok=True)

    good(f"=== target: {host} ===")

    state_store = None if runner.dry_run else StateStore(runner.outdir, host, flat=runner.flat)
    # --ad/--web reuse a prior run's ports/services, so they need the state loaded
    # too, not only --resume.
    focused = getattr(args, "ad", False) or getattr(args, "web", False)
    if (args.resume or focused) and state_store:
        state_store.load()
        # A focused re-enum (--ad/--web) reuses cached ports/services but must
        # actually RE-RUN its enum modules - so drop the prior run's job-status
        # map, which JobQueue.add_job() would otherwise honour and skip a module
        # a normal scan already marked "done". --resume keeps it (that's its job).
        if focused and not args.resume:
            state_store.data["jobs"] = {}
    if state_store:
        state_store.data["mode"] = args.mode
        state_store.data["started_at"] = state_store.data.get("started_at") or \
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    findings = FindingsList(state_store=state_store, dry_run=runner.dry_run)
    if args.resume and state_store and state_store.data.get("findings"):
        for sev, svc, port, text in state_store.data["findings"]:
            findings.seed(Finding(sev, svc, port, text))
        if findings:
            info(f"resume: restored {len(findings)} cached finding(s) for {host}")

    async with JobQueue(workers=args.workers, state_store=state_store) as queue:
        queue.add_job(Job(f"{host}:discover", PRIO_DISCOVER, background=False, always_reenter=True,
            coro_factory=functools.partial(job_discover, host, runner, args, queue,
                                            findings, host_profile, host_state, state_store)))
        await queue.wait_core_done()

        if not host_state["ports"]:
            return

        elapsed = time.time() - t0
        if not runner.dry_run:
            print_summary(host, host_state["services"], host_state["udp"], findings,
                          host_profile, elapsed, args)
            md = _write_notes(host, host_state, findings, host_profile, runner, args)
            good(f"notes written: {md}")
            _merge_workspace(host, host_state, findings, host_profile, runner, args)
            _sync_exam(host, host_state, findings, host_profile, runner, args)

        if queue.had_background_jobs:
            info("background modules (udp/vuln-scan) still running - "
                 "NOTES.md will be refreshed when they finish")
        await queue.wait_all_done()
        if not runner.dry_run and queue.had_background_jobs:
            elapsed = time.time() - t0
            print_summary(host, host_state["services"], host_state["udp"], findings,
                          host_profile, elapsed, args)
            _write_notes(host, host_state, findings, host_profile, runner, args)
            _merge_workspace(host, host_state, findings, host_profile, runner, args)
            _sync_exam(host, host_state, findings, host_profile, runner, args)
            good(f"{host}: background modules finished - notes updated")


# --------------------------------------------------------------------------- #
#  Targets
# --------------------------------------------------------------------------- #
def expand_targets(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 1:
            return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass
    return [target]


async def spray_credential(hosts, runner, args):
    """Test ONE credential across many hosts via SMB (and WinRM). netexec accepts
    a space-separated host list, so this is a single fast pass per protocol.
    Deliberately sprays a SINGLE credential to avoid account lockout."""
    nxc = nxc_bin()
    if not nxc:
        bad("spray needs netexec/nxc - not found.")
        return
    auth = nxc_auth(args)
    targets = " ".join(hosts)
    good(f"spraying {C.M}{cred_label(args)}{C.END} across {len(hosts)} host(s) via SMB/WinRM")
    findings = FindingsList()
    os.makedirs(os.path.join(runner.outdir, "_spray"), exist_ok=True)
    locked_out = False
    for proto in ("smb", "winrm"):
        rc, out = await runner.run(f"{nxc} {proto} {targets} {auth}",
                                   f"_spray/{proto}.txt", f"spray-{proto}",
                                   timeout=args.scan_timeout)
        # surface each valid host / admin
        for line in (out or "").splitlines():
            if "(Pwn3d!)" in line:
                findings.append(Finding("CRITICAL", proto, None, f"ADMIN: {line.strip()}"))
            elif re.search(r"\[\+\]", line):
                findings.append(Finding("HIGH", proto, None, f"valid: {line.strip()}"))
            elif "STATUS_ACCOUNT_LOCKED_OUT" in line:
                findings.append(Finding("HIGH", "creds", None, "LOCKOUT hit - stop now"))
                bad("account lockout detected - stopping spray")
                locked_out = True
                break
        if locked_out:
            break
    # report
    print(f"\n{C.BOLD}{'='*70}{C.END}")
    print(f"{C.BOLD}  SPRAY RESULTS  -  {cred_label(args)}{C.END}")
    print(f"{C.BOLD}{'='*70}{C.END}")
    if findings:
        findings.sort(key=lambda f: SEV_ORDER.get(f.sev, 9))
        for f in findings:
            print(f"    {SEV_COLOR.get(f.sev,'')}{f.sev:<8}{C.END} {C.DIM}{f.service}{C.END}  {f.text}")
        print(f"\n  {C.B}->{C.END} For any (Pwn3d!) SMB host: dump SAM / secrets. "
              f"For WinRM valid: evil-winrm -i <host> -u {args.user} ...")
    else:
        print(f"  {C.DIM}Credential not valid on any host via SMB/WinRM. Try other protocols "
              f"(mssql/rdp/ssh) or another host set.{C.END}")
    print(f"{C.BOLD}{'='*70}{C.END}\n")


async def ping_sweep(hosts, args):
    """Quick liveness check so we don't waste time on dead hosts in a /24."""
    alive = []
    sem = asyncio.Semaphore(256)

    async def check(h):
        async with sem:
            # TCP-ping common ports; ICMP needs root and is often filtered
            for p in (445, 80, 22, 443, 135):
                if await tcp_connect(h, p, timeout=1.0):
                    alive.append(h); return

    await asyncio.gather(*(check(h) for h in hosts))
    return sorted(alive, key=lambda x: tuple(int(o) for o in x.split(".")) if x.count(".")==3 and all(o.isdigit() for o in x.split(".")) else (0,))


# Hand-written, not generated from build_argparser() - a man page reads as
# prose grouped by workflow (MODES, AUTHENTICATED MODE, ...), not a flat flag
# dump like --help. That means it does NOT auto-track argparser changes:
# keep it in sync by hand whenever a flag/default in build_argparser() changes.
MANUAL = """
RECONX(1)                        reconx manual                      RECONX(1)

NAME
    reconx - lean, fast, accurate recon orchestrator (AutoRecon alternative)

SYNOPSIS
    reconx TARGET [options]

DESCRIPTION
    reconx discovers open ports fast, confirms them for accuracy with
    nmap -sCV, runs targeted per-service enumeration concurrently, then
    prints a ranked "look at this first" summary instead of burying you
    in hundreds of loose files. TARGET is an IP, hostname, or CIDR range
    (e.g. 10.10.10.10, target.htb, 10.10.10.0/24).

    Only use this against systems you're authorized to test: your own
    lab, HTB/PG/THM, or written permission.

HOW A SCAN RUNS
    1. Discovery      rustscan if installed, else a built-in async TCP
                       connect sweep (all 65535 ports by default). If the
                       first pass finds 0 open ports, reconx retries once
                       at lower concurrency before reporting the host down
                       (bursts of connections can trip rate-limiting).
    2. Accuracy pass   nmap -sCV on the confirmed ports for real service
                       and version info, with a UDP scan running alongside.
    3. Enumeration     per-service modules run concurrently as ports are
                       confirmed: SMB
                       and AD (netexec/enum4linux-ng/smbclient/ldapsearch),
                       remote access (FTP/SSH/RDP/WinRM), databases
                       (MSSQL/PostgreSQL/Redis), SNMP, SMTP/POP3/IMAP,
                       NFS, DNS.
    4. Findings        regex rules classify tool output into CRITICAL /
                       HIGH / MEDIUM / INFO, deduplicated and ranked.
    5. Output          colored terminal summary + a NOTES.md per host,
                       ready to drop into your report.

MODES  (--mode quick|full|deep, default: full)
    quick   top-1000 ports only, no UDP, no nmap -sC scripts. For a first
            pass across many hosts. Same as passing --quick.
    full    all 65535 TCP ports, UDP scan, nmap -sC scripts. The default.
    deep    like full, plus heavier vuln-scan scripts turned on
            automatically and a higher nmap version-detection intensity.

BASIC OPTIONS
    -o, --outdir DIR       where results are written (default: reconx-results)
    --mode MODE             quick | full | deep (see MODES above)
    --quick                 shorthand for --mode quick
    --top-ports N           scan only the top N common ports
    --no-udp                skip the UDP scan
    --no-scripts             nmap -sV only, skip -sC
    --no-rustscan           force the built-in async scanner over rustscan
    --ping-sweep            liveness-check a CIDR before scanning it
    --dry-run                print the command plan, run nothing
    --resume                skip jobs already completed under outdir/host/,
                            so a Ctrl-C or crash doesn't cost you the work
                            already done - just re-run the same command
    -v, --verbose            echo every external command as it runs
    --no-color               disable colored output

AUTHENTICATED MODE
    Feed reconx a credential and the SMB/WinRM/LDAP/MSSQL/SSH/Postgres
    modules re-run authenticated: checking access, admin rights (Pwn3d!),
    shares, users, and AD Kerberoast/AS-REP roasting, printing the exact
    follow-up command (evil-winrm, xfreerdp, BloodHound, ...) the moment a
    login is confirmed to work.

    -u, --user NAME         username for authenticated enumeration
    -p, --pass PASS         password (use --hash instead for NTLM)
    -H, --hash HASH         NTLM hash for pass-the-hash (LM:NT or :NT)
    -d, --domain DOMAIN     AD domain (e.g. corp.htb)
    --local-auth            treat the credential as a LOCAL account, not
                            a domain account
    --spray                 test the ONE supplied credential across every
                            host in a CIDR via SMB/WinRM, then stop
                            (doesn't full-scan the whole range)
    --ad                    AD-focused re-enum: reuse the ports/services from
                            a prior run's state file (or a quick DC-port probe
                            if there's no cache), skip general discovery and
                            every non-AD module, and run only the AD suite
                            (SMB/LDAP/Kerberos/DNS/WinRM) with the -u/-p/-H/-d
                            credential. The fast "got a cred, re-hit the DC"
                            loop - no second full port scan.
                            Creds are NOT persisted between runs: each --ad run
                            authenticates with the creds you pass it, so running
                            --ad with a different credential is fine (it re-runs
                            the AD modules fresh). It only touches the AD suite,
                            though - non-AD output from a prior run is left as-is,
                            not refreshed with the new creds.
    --bloodhound            once authenticated to LDAP, also run a full
                            bloodhound-python -c All collection in the
                            background (needs bloodhound-python installed)

    Credential reuse is the fastest path from foothold to root. --spray
    only ever tries a single credential (never a list) and stops on
    STATUS_ACCOUNT_LOCKED_OUT, but confirm the target's lockout policy
    before spraying a domain account regardless. Authenticated checks
    need netexec (nxc) installed.

WEB ENUMERATION
    An initial scan only FINGERPRINTS web ports (whatweb + a root grab) -
    the slow directory brute is deliberately NOT run, because it dominated
    scan time. When a host looks worth it, re-run with --web for the deep
    pass, exactly like --ad but for the web surface.

    --web                   web-focused deep re-enum: reuse the cached
                            ports/services from a prior run (or a quick
                            web-port probe if there's no cache), skip every
                            non-web module, and run the deep pass on each web
                            port - directory brute (feroxbuster, else
                            gobuster, else ffuf) + nikto, plus once-per-host
                            virtual-host fuzzing (ffuf -ac / gobuster vhost
                            against Host: FUZZ.<domain>, domain from -d, a
                            hostname target, or a root redirect). No second
                            full port scan.
    --no-web                skip web enumeration entirely (not even the
                            fingerprint)
    --web-timeout SECONDS   max seconds for the per-web-port directory
                            brute under --web (default 180)

TUNING / ADVANCED
    --concurrency N          async port-scan concurrency (default 800; if
                            discovery finds 0 ports, reconx auto-retries
                            once at a lower value before giving up)
    --parallel N              max concurrent external commands (default 6)
    --workers N                enum job-queue worker count (default 8)
    --version-intensity N      nmap --version-intensity for -sCV (0-9;
                              default 6, 9 in --mode deep)
    --host-timeout SECONDS     per-port connect timeout (default 1.5)
    --scan-timeout SECONDS      port/service scan timeout (default 1800)
    --enum-timeout SECONDS       per-enum-module timeout (default 600)
    --timeout SECONDS             default command timeout (default 900)
    --no-exploit-search           skip searchsploit correlation

OUTPUT LAYOUT
    reconx-results/
    +-- 10.10.10.10/
        +-- scans/       rustscan, nmap service, nmap udp
        +-- smb/         netexec, enum4linux-ng, smbclient
        +-- ldap/        rootdse dump, anon dump, kerberoast/asrep loot
        +-- ftp/ ssh/ snmp/ nfs/ ...
        +-- NOTES.md     ports table + ranked findings, ready for your report

EXAMPLES
    reconx 10.10.10.10
        single host, full pipeline

    reconx 10.10.10.10 --quick
        fast top-1000-port pass

    reconx 10.10.10.0/24 --ping-sweep --quick
        sweep a subnet, then quick-scan whatever answers

    reconx target.htb -o loot/
        write results under loot/ instead of reconx-results/

    reconx 10.10.10.10 --web
        deep web re-enum (dir-brute + nikto) reusing the earlier scan's ports

    reconx 10.10.10.10 --dry-run
        see the exact command plan without running anything

    reconx 10.10.10.10 --resume
        pick up an interrupted scan where it left off

    reconx dc01.corp.htb -u alex.turner -p 'Passw0rd!' -d corp.htb
        authenticated AD enumeration with a domain credential

    reconx 10.10.10.5 -u admin -H <LM:NT> --local-auth
        pass-the-hash against a local account

    reconx 10.10.10.0/24 -u svc -p 'S3cret!' --spray
        spray one credential across a subnet, then stop

    reconx dc01.corp.htb -u alex.turner -p 'Passw0rd!' -d corp.htb --bloodhound
        authenticated enum plus a full BloodHound collection

REQUIREMENTS
    Python 3.8+, standard library only. Everything else (rustscan, nmap,
    nxc/netexec, enum4linux-ng, impacket, ...) is
    optional - reconx prints what it found and what it's skipping, and
    each module degrades gracefully when its tool is missing.

SEE ALSO
    reconx --help    for the flag reference in short form
    README.md        for the full writeup and extension guide

    Authorized targets only.
"""


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
class _ManAction(argparse.Action):
    """Prints the full manual and exits immediately, the same way argparse's
    built-in -h/--help does - so `reconx --man` works even without a target
    positional (its required-ness is only checked *after* parsing)."""

    def __init__(self, option_strings, dest, help=None):
        super().__init__(option_strings=option_strings, dest=dest,
                         nargs=0, default=argparse.SUPPRESS, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print(MANUAL)
        parser.exit()


def build_argparser():
    p = argparse.ArgumentParser(
        prog="reconx",
        description="Lean, fast, accurate recon orchestrator (AutoRecon alternative).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Authorized targets only. Examples:\n"
               "  reconx 10.10.10.10\n"
               "  reconx 10.10.10.0/24 --ping-sweep --quick\n"
               "  reconx target.htb -o loot/\n"
               "  reconx dc01.corp.htb -u alex.turner -p 'Passw0rd!' -d corp.htb\n"
               "  reconx 10.10.10.0/24 -u svc -H <ntlm-hash> --spray\n"
               "  reconx 10.10.10.10 --dry-run",
    )
    p.add_argument("--man", action=_ManAction,
                   help="show the full manual (usage guide + examples) and exit")
    p.add_argument("target", help="IP, hostname, or CIDR (e.g. 10.10.10.0/24)")
    p.add_argument("-o", "--outdir", default="reconx-results", help="output directory")
    # --- credentials (authorized testing only) ---
    cg = p.add_argument_group("credentials (authenticated enumeration)")
    cg.add_argument("-u", "--user", help="username for authenticated enum")
    cg.add_argument("-p", "--pass", dest="password", help="password (use --hash for NTLM)")
    cg.add_argument("-H", "--hash", help="NTLM hash for pass-the-hash (LM:NT or :NT)")
    cg.add_argument("-d", "--domain", help="AD domain (e.g. corp.htb)")
    cg.add_argument("--local-auth", action="store_true", help="treat creds as LOCAL account, not domain")
    cg.add_argument("--spray", action="store_true",
                    help="spray the ONE credential across all hosts (CIDR) via SMB/WinRM")
    cg.add_argument("--ad", action="store_true",
                    help="AD-focused re-enum: reuse cached ports (or a quick DC-port "
                         "probe), skip general discovery + non-AD modules, and run only "
                         "the AD suite (SMB/LDAP/Kerberos/DNS/WinRM) with the -u/-p/-H/-d creds")
    p.add_argument("--mode", choices=("quick", "full", "deep"), default=None,
                   help="scan profile: quick (fast, no UDP/scripts), full (default), "
                        "deep (heavier vuln-scan scripts auto-on)")
    p.add_argument("--quick", action="store_true", help="top-1000 ports only (fast); shorthand for --mode quick")
    p.add_argument("--top-ports", type=int, help="scan only the top N common ports")
    p.add_argument("--no-udp", action="store_true", help="skip UDP scan")
    p.add_argument("--no-scripts", action="store_true", help="nmap -sV only, no -sC")
    p.add_argument("--no-rustscan", action="store_true", help="force built-in async scanner")
    p.add_argument("--bloodhound", action="store_true",
                   help="run a full BloodHound collection (-c All) against an authenticated LDAP target (backgrounded)")
    p.add_argument("--ping-sweep", action="store_true", help="liveness-check a CIDR first")
    p.add_argument("--concurrency", type=int, default=800,
                   help="async scan concurrency (auto-retries once at a lower "
                        "concurrency if the first pass finds 0 ports, in case "
                        "a rate-limiting host/firewall dropped the burst)")
    p.add_argument("--parallel", type=int, default=6, help="max concurrent external commands")
    p.add_argument("--workers", type=int, default=8,
                   help="job-queue worker pool size (how many modules run at once)")
    p.add_argument("--version-intensity", type=int, default=None,
                   help="nmap --version-intensity for -sCV (default 6, 9 in --mode deep)")
    p.add_argument("--host-timeout", type=float, default=1.5, help="per-port connect timeout (s)")
    p.add_argument("--scan-timeout", type=int, default=1800, help="port/service scan timeout (s)")
    p.add_argument("--enum-timeout", type=int, default=600, help="per-enum-module timeout (s)")
    p.add_argument("--timeout", type=int, default=900, help="default command timeout (s)")
    p.add_argument("--dry-run", action="store_true", help="print the command plan, run nothing")
    p.add_argument("--resume", action="store_true",
                   help="skip commands whose output file already exists in outdir (resume an interrupted run)")
    p.add_argument("--no-exploit-search", action="store_true",
                   help="skip searchsploit lookups for detected service versions")
    p.add_argument("--no-web", action="store_true",
                   help="skip automated web enumeration (whatweb fingerprint)")
    p.add_argument("--web", action="store_true",
                   help="web-focused deep re-enum: reuse cached ports (or a quick "
                        "web-port probe), skip non-web modules, and run the deep web "
                        "pass (dir-brute + nikto + vhost fuzzing). Initial scans are fingerprint-only.")
    p.add_argument("--web-timeout", type=int, default=180,
                   help="max seconds for the per-web-port directory brute (default 180)")
    p.add_argument("-v", "--verbose", action="store_true", help="print every command as it runs")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    # --- exam integration (companion modules) ---
    xg = p.add_argument_group("exam / notes integration")
    xg.add_argument("--exam", metavar="NAME",
                    help="register this scan in an exam (see 'reconx exam'); "
                         "default: the current exam if one exists")
    xg.add_argument("--points", type=int,
                    help="point value when auto-adding this target to the exam (default 20)")
    xg.add_argument("--set", dest="exam_set", metavar="NAME",
                    help="group this target into a named set (e.g. AD) in the exam")
    xg.add_argument("--no-vault", action="store_true",
                    help="don't touch the Obsidian vault note (still writes per-host NOTES.md)")
    xg.add_argument("--workspace", metavar="DIR",
                    help="PakCyberbot box workspace (~/ACTIVE_PENTEST/<box>): output "
                         "goes to DIR/scans/reconx and findings merge into DIR/notes.md")
    return p


BANNER = r"""
                              __  __
  _ __ ___  ___ ___  _ __ __ _\ \/ /   lean . fast . accurate
 | '__/ _ \/ __/ _ \| '_ \ \ / /\  /   an AutoRecon alternative
 | | |  __/ (_| (_) | | | \ V / /  \   authorized targets only
 |_|  \___|\___\___/|_| |_|_/_/  /_/\_\
"""

# top-1000-ish common TCP ports for --quick and the async fallback
TOP_1000 = [1,3,7,9,13,17,19,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1434,1521,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3268,3269,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,5985,5986,6000,6001,6379,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9200,9999,10000,27017,32768,49152,49153,49154,49155,49156,49157]


def apply_mode_defaults(args):
    """Resolve --mode into the underlying flags. Mode defaults only ever
    strengthen a store_true flag from False->True, never the reverse -
    Python 3.8 (this tool's floor) has no reliable way to detect "the user
    explicitly passed --no-X" for a plain store_true flag, so an explicit
    flag can only ever be left alone or turned on by mode, never overridden
    off. --mode quick forcing no_udp/no_scripts True is a known, accepted
    limitation: there's no way to un-force that short of not using that mode.
    """
    if args.mode is None:
        args.mode = "quick" if args.quick else "full"
    elif args.mode == "quick":
        args.quick = True

    if args.mode == "quick":
        args.no_udp = True
        args.no_scripts = True
    elif args.mode == "deep":
        if args.version_intensity is None:
            args.version_intensity = 9
    return args.mode


async def amain(args):
    apply_mode_defaults(args)
    # PakCyberbot workspace: default output into the box's existing scans/ dir
    # unless the user gave an explicit -o. Reuses the workspace, never a new tree.
    if getattr(args, "workspace", None):
        args.workspace = os.path.expanduser(args.workspace)
        if args.outdir == "reconx-results":
            args.outdir = os.path.join(args.workspace, "scans", "reconx")
    refresh_tools()
    runner = Runner(args.outdir, dry_run=args.dry_run,
                    timeout=args.timeout, verbose=args.verbose, resume=args.resume)
    runner.sem = asyncio.Semaphore(args.parallel)

    print(C.CY + BANNER + C.END)
    info(f"mode: {C.M}{args.mode}{C.END}  workers: {args.workers}  parallel: {args.parallel}")
    have, missing = tool_availability()
    info(f"tools available: {C.G}{', '.join(have) or 'none'}{C.END}")
    if missing:
        warn(f"missing (modules will degrade/skip): {C.DIM}{', '.join(missing)}{C.END}")

    # credential status + safety
    if have_creds(args):
        good(f"authenticated mode: {C.M}{cred_label(args)}{C.END}")
        if not nxc_bin():
            warn("no netexec/nxc found - authenticated checks need it; install netexec")
        if not args.local_auth and not args.domain:
            warn("no -d/--domain set with a domain account - some AD checks may fail; add -d, or --local-auth for local accounts")
        if args.spray and not args.local_auth:
            warn(f"{C.R}SPRAY on a DOMAIN account can trigger lockout.{C.END} "
                 f"reconx sprays ONE credential (not many) to stay safe, but confirm the lockout policy first.")
    elif args.spray:
        bad("--spray needs a credential (-u with -p or -H). Ignoring.")
        args.spray = False

    if getattr(args, "web", False) and getattr(args, "no_web", False):
        warn("--web with --no-web is contradictory - --web wins; enabling web enum.")
        args.no_web = False

    if getattr(args, "ad", False) and getattr(args, "web", False):
        warn("--ad and --web are both focused re-enum modes - can't combine; "
             "keeping --ad and ignoring --web this run.")
        args.web = False

    if getattr(args, "ad", False):
        if have_creds(args):
            good(f"--ad: AD-focused re-enum with {C.M}{cred_label(args)}{C.END} "
                 f"(reusing cached ports; non-AD modules skipped)")
        else:
            warn("--ad without credentials - running UNAUTHENTICATED AD enum "
                 "(null/guest only). Add -u/-p/-H (+ -d) for the full AD suite.")
    elif getattr(args, "web", False):
        good("--web: web-focused deep re-enum (dir-brute + nikto; reusing cached "
             "ports; non-web modules skipped)")

    hosts = expand_targets(args.target)
    if len(hosts) > 1 and args.ping_sweep and not args.dry_run:
        info(f"ping-sweeping {len(hosts)} hosts...")
        hosts = await ping_sweep(hosts, args)
        good(f"{len(hosts)} host(s) alive")

    # spray path: one credential across many hosts, then stop (don't full-scan the /24)
    if args.spray and have_creds(args) and len(hosts) > 1:
        await spray_credential(hosts, runner, args)
        return

    # --workspace runs one host per invocation, and its workspace path is already
    # per-host (base/<ip>), so drop reconx's own <host> subdir - output lands at
    # <workspace>/scans/reconx/ instead of the redundant .../reconx/<ip>/. Only
    # when a single host resolved, so a manual `reconx <cidr> --workspace` still
    # namespaces per host and can't collide.
    if getattr(args, "workspace", None) and len(hosts) == 1:
        runner.flat = True

    if len(hosts) > 1:
        info(f"scanning {len(hosts)} host(s) sequentially (per-host modules run in parallel)")

    for h in hosts:
        try:
            await scan_host(h, runner, args)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            bad(f"{h}: error - {e}")

    if args.dry_run:
        print(f"\n{C.BOLD}=== DRY RUN: command plan ({len(runner.plan)} commands) ==={C.END}")
        for label, cmd, outfile in runner.plan:
            print(f"  {C.G}{label:<16}{C.END} {cmd}")
        print(f"\n{C.DIM}No commands were executed.{C.END}\n")


def main():
    # `reconx exam ...` -> delegate to the companion exam manager (no scan).
    if len(sys.argv) > 1 and sys.argv[1] == "exam":
        if reconx_exam is None:
            print("reconx_exam module not found (place reconx_exam.py next to reconx.py)",
                  file=sys.stderr)
            sys.exit(1)
        sys.exit(reconx_exam.exam_cli(sys.argv[2:]))
    args = build_argparser().parse_args()
    if args.no_color or not sys.stdout.isatty():
        C.strip()
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] interrupted - partial results are on disk.{C.END}")
        sys.exit(130)


if __name__ == "__main__":
    main()
