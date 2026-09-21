"""Unit tests for reconx's pure (side-effect-free) helpers.

These cover parsing, service/host classification, credential-string building,
the findings regex engine, note wikilinks, and the flat-mode path logic - the
functions that carry the tool's logic without touching the network, the disk,
or external tools, so they can be asserted directly.

Run:  cd reconx && python3 -m pytest -q
"""
import os
import types

import pytest

import reconx
import reconx_notes


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
