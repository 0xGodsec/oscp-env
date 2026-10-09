"""Unit tests for reconx's pure (side-effect-free) helpers.

These cover parsing, service/host classification, credential-string building,
the findings regex engine, note wikilinks, and the flat-mode path logic - the
functions that carry the tool's logic without touching the network, the disk,
or external tools, so they can be asserted directly.

Run:  cd reconx && python3 -m pytest -q
"""
import importlib.machinery
import importlib.util
import json
import os
import tempfile
import types

import pytest

import reconx
import reconx_notes


def _load_recon_exam():
    """recon-exam has no .py extension, so load it by path for testing."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "recon-exam")
    loader = importlib.machinery.SourceFileLoader("recon_exam", path)
    spec = importlib.util.spec_from_loader("recon_exam", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _args(**kw):
    """A minimal argparse-like object. reconx's cred helpers read attributes
    via getattr with defaults, so an empty namespace is a valid 'no creds'."""
    return types.SimpleNamespace(**kw)


# --------------------------------------------------------------------------- #
# Port-scan output parsing
# --------------------------------------------------------------------------- #
class TestParsing:
    def test_rustscan_arrow_format(self):
        assert reconx.parse_rustscan_greppable("10.0.0.1 -> [22,80,443]") == [22, 80, 443]

    def test_rustscan_open_format(self):
        out = "Open 10.0.0.1:22\nOpen 10.0.0.1:445"
        assert reconx.parse_rustscan_greppable(out) == [22, 445]

    def test_rustscan_dedupes_and_sorts(self):
        assert reconx.parse_rustscan_greppable("h -> [443, 22, 443]") == [22, 443]

    def test_rustscan_empty(self):
        assert reconx.parse_rustscan_greppable("no ports here") == []

    def test_nmap_ports(self):
        out = (
            "PORT     STATE SERVICE   VERSION\n"
            "22/tcp   open  ssh       OpenSSH 8.2\n"
            "445/tcp  open  microsoft-ds\n"
            "80/tcp   closed http\n"
        )
        svc = reconx.parse_nmap_ports(out)
        assert set(svc) == {22, 445}
        assert svc[22] == {"name": "ssh", "version": "OpenSSH 8.2"}
        assert svc[445] == {"name": "microsoft-ds", "version": ""}

    def test_nmap_udp_open_and_open_filtered(self):
        # "open|filtered" (the common UDP state, incl. real SNMP/TFTP) must not
        # be dropped - regression for the old `\s+open\s+` parser.
        out = (
            "PORT    STATE         SERVICE\n"
            "161/udp open          snmp\n"
            "69/udp  open|filtered tftp\n"
            "53/udp  closed        domain\n"
        )
        udp = reconx.parse_nmap_udp(out)
        assert set(udp) == {161, 69}
        assert udp[161] == "snmp"                     # confirmed open: bare name
        assert udp[69] == "tftp (open|filtered)"      # uncertain: labelled
        assert 53 not in udp                          # closed: dropped


# --------------------------------------------------------------------------- #
# Service / host classification
# --------------------------------------------------------------------------- #
class TestClassification:
    def test_guess_service_known(self):
        assert reconx.guess_service(445) == "microsoft-ds"

    def test_guess_service_unknown(self):
        assert reconx.guess_service(12345) == "unknown"

    @pytest.mark.parametrize("port,name", [(80, ""), (9200, ""), (443, ""), (12345, "http-alt")])
    def test_is_web_true(self, port, name):
        assert reconx.is_web(port, name) is True

    @pytest.mark.parametrize("port,name", [(22, "ssh"), (445, "microsoft-ds")])
    def test_is_web_false(self, port, name):
        assert reconx.is_web(port, name) is False

    def test_host_type_ad_two_ad_ports(self):
        assert reconx.classify_host_type({88, 389}, {}) == "ad"

    def test_host_type_ad_one_ad_port_plus_smb(self):
        assert reconx.classify_host_type({88, 445}, {}) == "ad"

    def test_host_type_samba_banner_is_linux_not_windows(self):
        # 445 alone would guess windows; a confirmed Samba banner must win.
        svc = {445: {"name": "netbios-ssn", "version": "Samba 4.11.6"}}
        assert reconx.classify_host_type({445}, svc) == "linux"

    def test_host_type_windows_via_rdp(self):
        assert reconx.classify_host_type({3389}, {}) == "windows"

    def test_host_type_linux_via_ssh(self):
        assert reconx.classify_host_type({22}, {}) == "linux"

    def test_host_type_windows_smb_only_fallback(self):
        assert reconx.classify_host_type({445}, {}) == "windows"

    def test_host_type_web(self):
        assert reconx.classify_host_type({80, 443}, {}) == "web"

    def test_is_ad_port_by_number(self):
        assert reconx._is_ad_port(389, "ldap") is True

    def test_is_ad_port_by_name_hint_on_odd_port(self):
        assert reconx._is_ad_port(12345, "ldap") is True

    def test_is_ad_port_false(self):
        assert reconx._is_ad_port(22, "ssh") is False

    @pytest.mark.parametrize("port,name,scheme", [
        (443, "", "https"),
        (8080, "ssl/http", "https"),
        (80, "", "http"),
        (80, "http", "http"),
    ])
    def test_web_scheme(self, port, name, scheme):
        assert reconx._web_scheme(port, name) == scheme

    def test_service_priority_fallback(self):
        assert reconx._service_priority("nonexistent", "nonexistent") == reconx.PRIO_ENUM


# --------------------------------------------------------------------------- #
# searchsploit term building
# --------------------------------------------------------------------------- #
class TestSearchsploitTerms:
    def test_full_phrase_first(self):
        terms = reconx._searchsploit_terms("Samba smbd 3.0.20-Debian")
        assert terms[0] == "Samba smbd 3.0.20"
        assert "Samba 3.0.20" in terms  # two-word name -> vendor+version fallback

    def test_no_version_returns_empty(self):
        assert reconx._searchsploit_terms("Some Server without a version") == []

    def test_none_returns_empty(self):
        assert reconx._searchsploit_terms(None) == []


# --------------------------------------------------------------------------- #
# Credential-string helpers
# --------------------------------------------------------------------------- #
class TestCreds:
    def test_have_creds_true_with_password(self):
        assert reconx.have_creds(_args(user="alex", password="pw")) is True

    def test_have_creds_true_with_hash(self):
        assert reconx.have_creds(_args(user="alex", hash="deadbeef")) is True

    def test_have_creds_false_no_user(self):
        assert reconx.have_creds(_args(password="pw")) is False

    def test_have_creds_false_no_secret(self):
        assert reconx.have_creds(_args(user="alex")) is False

    def test_nxc_auth_password_and_domain(self):
        r = reconx.nxc_auth(_args(user="alex", password="P@ss w0rd!", domain="corp.htb"))
        assert "-u alex" in r
        assert "-d corp.htb" in r
        # a password with shell metacharacters must be quoted, not bare
        assert "P@ss w0rd!" not in r.replace("'P@ss w0rd!'", "")

    def test_nxc_auth_hash_not_password(self):
        r = reconx.nxc_auth(_args(user="alex", hash="deadbeef"))
        assert "-H deadbeef" in r
        assert "-p " not in r

    def test_nxc_auth_local_auth_flag(self):
        r = reconx.nxc_auth(_args(user="a", password="b", local_auth=True))
        assert "--local-auth" in r

    def test_cred_label_uses_placeholders(self):
        label = reconx.cred_label(_args(user="alex", domain="corp"))
        assert label == r"corp\alex:<pass> (domain)"

    def test_cred_label_never_leaks_secret(self):
        label = reconx.cred_label(_args(user="alex", password="s3cr3t"))
        assert "s3cr3t" not in label


# --------------------------------------------------------------------------- #
# Findings regex engine
# --------------------------------------------------------------------------- #
class TestScanFindings:
    def test_kerberoast_tgs_is_critical(self):
        found = []
        reconx.scan_findings("$krb5tgs$23$*svc$REALM$...", "ldap", 389, found)
        assert any(f.sev == "CRITICAL" and f.service == "ad" for f in found)

    def test_pwn3d_is_critical_admin(self):
        found = []
        reconx.scan_findings("SMB  10.0.0.1  445  DC  [+] corp\\alex (Pwn3d!)", "smb", 445, found)
        assert any(f.sev == "CRITICAL" and "ADMIN" in f.text for f in found)

    def test_benign_text_no_findings(self):
        found = []
        reconx.scan_findings("nothing interesting on this port", "http", 80, found)
        assert found == []


# --------------------------------------------------------------------------- #
# Domain / hosts-line parsing (incl. security regressions)
# --------------------------------------------------------------------------- #
class TestDomainAndHosts:
    def test_dn_to_domain(self):
        assert reconx._dn_to_domain("DC=checkpoint,DC=htb") == "checkpoint.htb"

    def test_dn_to_domain_empty(self):
        assert reconx._dn_to_domain("") is None
        assert reconx._dn_to_domain(None) is None

    def test_hosts_line_legit(self):
        banner = "SMB  1.2.3.4  445  DC  [*] ... (name:DC) (domain:northstone.local) (signing:True) (DC:True)"
        line = reconx._hosts_line_from_banner("1.2.3.4", banner)
        assert line.startswith("1.2.3.4")
        assert "DC.northstone.local" in line
        assert line.endswith(" DC")

    def test_hosts_line_rejects_newline_injection(self):
        # a crafted banner must not smuggle extra /etc/hosts lines (security fix)
        evil = "(name:x\n6.6.6.6 evil.com) (domain:corp.local) (DC:True)"
        assert reconx._hosts_line_from_banner("1.2.3.4", evil) == ""

    def test_hosts_line_missing_domain(self):
        assert reconx._hosts_line_from_banner("1.2.3.4", "(name:DC)") == ""


# --------------------------------------------------------------------------- #
# Next-step suggestions
# --------------------------------------------------------------------------- #
class TestSuggestNext:
    def test_web_step_present(self):
        steps = reconx.suggest_next({80: {"name": "http"}}, [], {"dc_signals": 0})
        assert any("Web" in s for s in steps)

    def test_always_appends_full_range_reminder(self):
        steps = reconx.suggest_next({80: {"name": "http"}}, [], {"dc_signals": 0})
        assert "full-range TCP + UDP" in steps[-1]

    def test_empty_falls_back(self):
        steps = reconx.suggest_next({}, [], {"dc_signals": 0})
        assert any("Re-read raw output" in s for s in steps)


# --------------------------------------------------------------------------- #
# Flat-mode output path (Runner.hostdir) - locks in the --workspace fix
# --------------------------------------------------------------------------- #
class TestHostdir:
    def test_nested_by_default(self):
        r = reconx.Runner("/out")
        assert r.hostdir("1.2.3.4") == os.path.join("/out", "1.2.3.4")

    def test_flat_collapses_host_level(self):
        r = reconx.Runner("/out")
        r.flat = True
        assert r.hostdir("1.2.3.4") == "/out"


# --------------------------------------------------------------------------- #
# reconx_notes wikilinks
# --------------------------------------------------------------------------- #
class TestNotes:
    def test_service_links_ports_and_dc(self):
        services = {445: {"name": "microsoft-ds"}, 88: {"name": "kerberos-sec"}}
        links = reconx_notes.service_links(services, {"dc_signals": 2})
        assert "[[SMB]]" in links
        assert "[[Kerberos]]" in links
        assert "[[Active Directory]]" in links

    def test_service_links_deduped(self):
        # 445 and 139 both map to [[SMB]] - must appear once
        links = reconx_notes.service_links({139: {"name": "netbios-ssn"}, 445: {"name": "microsoft-ds"}})
        assert len(links) == len(set(links))
        assert links.count("[[SMB]]") == 1

    def test_host_type_of_ad(self):
        assert reconx_notes._host_type_of({"dc_signals": 2}) == "ad"

    def test_host_type_of_plain(self):
        assert reconx_notes._host_type_of({"dc_signals": 0, "host_type": "linux"}) == "linux"

    def test_host_type_of_none(self):
        assert reconx_notes._host_type_of(None) is None


# --------------------------------------------------------------------------- #
# ffuf JSON -> findings (F4: ffuf is now a real dir-brute fallback)
# --------------------------------------------------------------------------- #
class TestFfufParsing:
    SAMPLE = (
        '{"results":[{"url":"http://10.0.0.1/admin","status":200},'
        '{"url":"http://10.0.0.1/index.html","status":200},'
        '{"url":"http://10.0.0.1/.git/config","status":301}]}'
    )

    def test_ffuf_json_to_lines(self):
        lines = reconx._ffuf_json_to_lines(self.SAMPLE).splitlines()
        assert "200 GET http://10.0.0.1/admin" in lines
        assert "301 GET http://10.0.0.1/.git/config" in lines
        assert len(lines) == 3

    def test_ffuf_lines_feed_the_shared_parser(self):
        # the whole point of F4: ffuf output flows through the SAME tested
        # feroxbuster/gobuster parser, surfacing juicy paths as HIGH.
        found = []
        text = reconx._ffuf_json_to_lines(self.SAMPLE)
        reconx._web_paths_to_findings(text, "10.0.0.1", 80, found)
        assert any(f.sev == "HIGH" and "/admin" in f.text for f in found)
        assert any(f.sev == "HIGH" and ".git" in f.text for f in found)
        assert any(f.sev == "INFO" and "path(s)" in f.text for f in found)

    def test_ffuf_json_malformed_is_safe(self):
        assert reconx._ffuf_json_to_lines("not json") == ""
        assert reconx._ffuf_json_to_lines("") == ""
        assert reconx._ffuf_json_to_lines('{"results":null}') == ""


# --------------------------------------------------------------------------- #
# vhost fuzzing (F5): base-domain resolution + result parsing
# --------------------------------------------------------------------------- #
class TestVhostFuzzing:
    def test_is_ipv4(self):
        assert reconx._is_ipv4("10.129.58.62")
        assert not reconx._is_ipv4("ghostlink.htb")
        assert not reconx._is_ipv4("256.1.1.1")   # octet out of range
        assert not reconx._is_ipv4("1.2.3")        # not a quad

    def test_registrable_domain(self):
        assert reconx._registrable_domain("www.ghostlink.htb") == "ghostlink.htb"
        assert reconx._registrable_domain("ghostlink.htb") == "ghostlink.htb"
        assert reconx._registrable_domain("10.129.58.62") is None   # IP, not a name
        assert reconx._registrable_domain("localhost") is None      # single label
        assert reconx._registrable_domain("") is None

    def test_base_domain_prefers_explicit_flag(self):
        dom, redir = reconx._vhost_base_domain("10.129.58.62", _args(domain="corp.htb"), "")
        assert dom == "corp.htb" and redir is None

    def test_base_domain_from_hostname_target(self):
        dom, redir = reconx._vhost_base_domain("ghostlink.htb", _args(), "")
        assert dom == "ghostlink.htb" and redir is None

    def test_base_domain_from_redirect(self):
        # classic HTB lead: bare-IP target 302s to a name-based vhost.
        root = "HTTP/1.1 302 Found\r\nLocation: http://ghostlink.htb/\r\n\r\n"
        dom, redir = reconx._vhost_base_domain("10.129.58.62", _args(), root)
        assert dom == "ghostlink.htb" and redir == "ghostlink.htb"

    def test_base_domain_none_for_bare_ip(self):
        dom, redir = reconx._vhost_base_domain("10.129.58.62", _args(), "HTTP/1.1 200 OK\r\n\r\n")
        assert dom is None and redir is None

    def test_parse_ffuf_vhosts(self):
        text = "admin\ndev\n\nfoo bar\nadmin\n"   # blank + space-bearing + dup are dropped
        assert reconx._parse_ffuf_vhosts(text, "ghostlink.htb") == [
            "admin.ghostlink.htb", "dev.ghostlink.htb"]

    def test_parse_gobuster_vhosts(self):
        text = ("Found: dev.ghostlink.htb Status: 200 [Size: 100]\n"
                "Found: admin.ghostlink.htb (Status: 200)\n")
        assert reconx._parse_gobuster_vhosts(text) == [
            "dev.ghostlink.htb", "admin.ghostlink.htb"]


# --------------------------------------------------------------------------- #
# recon-exam reads ReconX's FLAT --workspace layout (regression: it used to
# read <ws>/scans/reconx/<ip>/, which ReconX never creates in flat mode, so
# domain detection + triage silently found nothing and Pass 2 never ran).
# --------------------------------------------------------------------------- #
class TestReconExamFlatPaths:
    def _flat_ws(self):
        rx = _load_recon_exam()
        ip = "10.129.58.62"
        ws = tempfile.mkdtemp()
        flat = os.path.join(ws, "scans", "reconx")   # NO per-ip subdir (flat mode)
        os.makedirs(flat)
        with open(os.path.join(flat, ".reconx_state.json"), "w") as f:
            json.dump({"target": ip, "ports": [88, 389, 445],
                       "findings": [["HIGH", "ad", 88, "Kerberos open"]]}, f)
        with open(os.path.join(flat, "smb_nxc.txt"), "w") as f:
            f.write("SMB 10.129.58.62 445 DC01 (name:DC01) (domain:ghostlink.htb) (DC:True)\n")
        return rx, ws, ip, flat

    def test_reconx_out_has_no_ip_segment(self):
        rx, ws, ip, flat = self._flat_ws()
        assert rx.reconx_out(ws) == flat
        assert not rx.reconx_out(ws).endswith(ip)

    def test_load_state_reads_flat_layout(self):
        rx, ws, ip, _ = self._flat_ws()
        st = rx.load_state(ws, ip)
        assert st.get("ports") == [88, 389, 445]      # empty {} before the fix
        assert st.get("findings")

    def test_identity_and_triage_populated(self):
        rx, ws, ip, _ = self._flat_ws()
        dom, fqdn, short = rx.extract_identity(rx.reconx_out(ws))
        assert dom == "ghostlink.htb"                 # None before the fix -> Pass 2 skipped
        assert short == "dc01"
        assert rx.classify_box(rx.load_state(ws, ip), dom) == "ad"


# --------------------------------------------------------------------------- #
# Tool-availability summary (F1: derived from the full TOOLS table, not a
# hardcoded subset, so a missing capability can't be silently hidden)
# --------------------------------------------------------------------------- #
class TestToolAvailability:
    def test_alias_group_counts_as_present(self, monkeypatch):
        # netexec present via the 'nxc' alias; enum4linux present via '-ng'.
        tools = {c: False for grp in reconx.CAPABILITY_GROUPS for c in grp[1]}
        tools["nxc"] = True
        tools["enum4linux-ng"] = True
        monkeypatch.setattr(reconx, "TOOLS", tools)
        present, missing = reconx.tool_availability()
        assert "nxc" in present                 # shows the actual found binary
        assert "enum4linux-ng" in present
        assert "netexec" not in missing         # the group is satisfied
        assert "enum4linux" not in missing

    def test_missing_capability_is_reported(self, monkeypatch):
        # Regression for F1: with only curl installed, every other capability
        # (ldapsearch, searchsploit, dir-brute, ...) MUST appear in 'missing'.
        tools = {c: False for grp in reconx.CAPABILITY_GROUPS for c in grp[1]}
        tools["curl"] = True
        monkeypatch.setattr(reconx, "TOOLS", tools)
        present, missing = reconx.tool_availability()
        assert present == ["curl"]
        for cap in ("ldapsearch", "searchsploit", "dir-brute", "nmap", "netexec", "smbclient"):
            assert cap in missing
