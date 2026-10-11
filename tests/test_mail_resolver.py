"""mail_resolver + the mail_ branch of task.resolve_cnames.

WHY THESE TESTS. The rows are read as "what this subdomain's mail routing was when we asked", so
the three ways to make them lie are pinned here: a failed lookup recorded as "no MX" / "no SPF",
a null MX recorded as a mail host, and a TXT record that merely mentions spf counted as one. The
source checks pin the path: the mail branch must keep the cname path's guarantee that a failed
file never reaches retries/ (and so never the lake), and must send its own dataset name.

Run: pytest tests/test_mail_resolver.py
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import dns.message
import pytest

import mail_resolver as M

REPO = Path(__file__).resolve().parents[1]


def _msg(qname, qtype, answer="", rcode="NOERROR"):
    return dns.message.from_text(
        f"id 1\nopcode QUERY\nrcode {rcode}\nflags QR RD RA\n;QUESTION\n{qname} IN {qtype}\n;ANSWER\n{answer}")


# ------------------------------------------------------------------ MX
def test_mx_records_are_sorted_by_preference_and_lowercased():
    r = M.parse_mx(_msg("bounce.acme.com.", "MX",
                        "bounce.acme.com. 300 IN MX 20 MXB.Mailgun.org.\n"
                        "bounce.acme.com. 300 IN MX 10 mxa.mailgun.org.\n"))
    assert r == {"mx_status": "PRESENT", "mx": ["10:mxa.mailgun.org", "20:mxb.mailgun.org"]}


def test_mx_behind_a_cname_is_the_targets_mx():
    r = M.parse_mx(_msg("em.acme.com.", "MX",
                        "em.acme.com. 300 IN CNAME u1.wl.sendgrid.net.\n"
                        "u1.wl.sendgrid.net. 300 IN MX 10 mx.sendgrid.net.\n"))
    assert r == {"mx_status": "PRESENT", "mx": ["10:mx.sendgrid.net"]}


def test_null_mx_is_its_own_status_and_not_a_host():
    assert M.parse_mx(_msg("x.acme.com.", "MX", "x.acme.com. 300 IN MX 0 .\n")) == \
        {"mx_status": "NULL_MX", "mx": []}


def test_no_mx_and_nxdomain_and_servfail_are_distinct():
    assert M.parse_mx(_msg("x.acme.com.", "MX"))["mx_status"] == "NO_MX"
    assert M.parse_mx(_msg("x.acme.com.", "MX", rcode="NXDOMAIN"))["mx_status"] == "NXDOMAIN"
    assert M.parse_mx(_msg("x.acme.com.", "MX", rcode="SERVFAIL"))["mx_status"] == "SERVFAIL"


# ------------------------------------------------------------------ TXT / SPF
def test_only_real_spf_records_are_kept_and_split_strings_are_joined():
    r = M.parse_txt(_msg("em.acme.com.", "TXT",
                         'em.acme.com. 300 IN TXT "v=spf1 include:send" "grid.net ~all"\n'
                         'em.acme.com. 300 IN TXT "google-site-verification=abc"\n'
                         'em.acme.com. 300 IN TXT "v=spf10 include:not-spf.example"\n'
                         'em.acme.com. 300 IN TXT "note: v=spf1 is our policy"\n'))
    assert r == {"txt_status": "PRESENT", "spf": ["v=spf1 include:sendgrid.net ~all"],
                 "spf_includes": ["sendgrid.net"]}


def test_txt_without_spf_is_present_with_no_spf():
    r = M.parse_txt(_msg("x.acme.com.", "TXT", 'x.acme.com. 300 IN TXT "hello"\n'))
    assert r == {"txt_status": "PRESENT", "spf": [], "spf_includes": []}


def test_no_txt_is_not_a_failure():
    assert M.parse_txt(_msg("x.acme.com.", "TXT"))["txt_status"] == "NO_TXT"
    assert M.parse_txt(_msg("x.acme.com.", "TXT", rcode="SERVFAIL"))["txt_status"] == "SERVFAIL"


def test_multiple_spf_records_are_all_kept():
    """Two v=spf1 records is a permerror; which one a receiver would have used is not ours to pick."""
    r = M.parse_txt(_msg("x.acme.com.", "TXT",
                         'x.acme.com. 300 IN TXT "v=spf1 include:b.example -all"\n'
                         'x.acme.com. 300 IN TXT "v=spf1 include:a.example -all"\n'))
    assert len(r["spf"]) == 2 and r["spf_includes"] == ["a.example", "b.example"]


def test_spf_includes_takes_include_and_redirect_and_drops_macros():
    assert M.spf_includes([
        "v=spf1 ip4:192.0.2.0/24 +include:_SPF.Google.com. ?include:mailgun.org "
        "include:%{i}._spf.example.com a mx redirect=_spf.acme.com"]) == \
        ["_spf.acme.com", "_spf.google.com", "mailgun.org"]


# ------------------------------------------------------------------ resolve_hosts
def _fake(answers, calls):
    async def lookup(host, rdtype, ns, timeout):
        calls.append((host, rdtype))
        v = answers[(host, rdtype)]
        return v.pop(0) if isinstance(v, list) else v
    return lookup


A_OK = {"rcode": "NOERROR", "cnames": [], "a": ["192.0.2.1"], "min_ttl": 60}
MX_OK = {"mx_status": "PRESENT", "mx": ["10:mx.esp.example"]}
TXT_OK = {"txt_status": "PRESENT", "spf": ["v=spf1 include:esp.example -all"], "spf_includes": ["esp.example"]}


def test_a_dead_name_is_not_asked_for_mail_records():
    calls = []
    rows = asyncio.run(M.resolve_hosts(
        ["gone.acme.com"], qps=1000,
        lookup=_fake({("gone.acme.com", "A"): {"rcode": "NXDOMAIN", "cnames": [], "a": [], "min_ttl": None}}, calls)))
    assert calls == [("gone.acme.com", "A")]
    assert (rows[0]["mx_status"], rows[0]["txt_status"], rows[0]["queries"]) == ("NOT_ASKED", "NOT_ASKED", 1)


def test_a_live_name_gets_all_three_and_counts_its_queries():
    calls = []
    rows = asyncio.run(M.resolve_hosts(
        ["em.acme.com"], qps=1000,
        lookup=_fake({("em.acme.com", "A"): A_OK, ("em.acme.com", "MX"): MX_OK,
                      ("em.acme.com", "TXT"): TXT_OK}, calls)))
    r = rows[0]
    assert (r["mx"], r["spf_includes"], r["queries"]) == (["10:mx.esp.example"], ["esp.example"], 3)


def test_a_failed_mx_lookup_is_retried_then_kept_as_a_failure_not_as_no_mx(monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr(M.asyncio, "sleep", no_sleep)
    calls = []
    timeout = {"mx_status": "TIMEOUT", "mx": []}
    rows = asyncio.run(M.resolve_hosts(
        ["em.acme.com"], qps=1000, retries=2,
        lookup=_fake({("em.acme.com", "A"): A_OK, ("em.acme.com", "MX"): timeout,
                      ("em.acme.com", "TXT"): TXT_OK}, calls)))
    assert rows[0]["mx_status"] == "TIMEOUT" and rows[0]["txt_status"] == "PRESENT"
    assert calls.count(("em.acme.com", "MX")) == 3 and rows[0]["queries"] == 5


def test_to_table_matches_the_schema():
    rows = asyncio.run(M.resolve_hosts(
        ["em.acme.com"], qps=1000,
        lookup=_fake({("em.acme.com", "A"): A_OK, ("em.acme.com", "MX"): MX_OK,
                      ("em.acme.com", "TXT"): TXT_OK}, [])))
    t = M.to_table(rows, source_file="mail_r1_00001.txt", worker="contabo54")
    assert t.schema.equals(M.SCHEMA) and t.num_rows == 1
    assert t.column("source_file")[0].as_py() == "mail_r1_00001.txt"


# ------------------------------------------------------------------ the path
def test_file_prefix_selects_the_mail_branch():
    assert M.is_mail_file("mail_20261011_00001.txt")
    assert not M.is_mail_file("cname_20261011_00001.txt")


def test_dataset_name_cannot_merge_into_an_existing_dataset():
    """r2_compactor names datasets by substring; `subdomains` is the one that would swallow it."""
    assert M.DATASET == "mail_resolution" and "subdomains" not in M.DATASET


def test_the_mail_branch_stays_on_the_cname_path():
    src = (REPO / "task.py").read_text(encoding="utf-8")
    body = src.split("def _resolve_mail(")[1].split("\n@app.task")[0]
    assert "dataset=mail_resolver.DATASET" in body
    assert "CNAME_DONE_FOLDER" in body
    assert "move_to_retries" not in body and "RETRIES" not in body.upper().replace("RETRIES INCLUDED", "")
    # It is called from inside resolve_cnames' try, so a failure takes the cname_failed/ route.
    task = src.split('name="task.resolve_cnames"')[1].split("except BaseException")[0]
    assert "return _resolve_mail(input_path, filename)" in task
