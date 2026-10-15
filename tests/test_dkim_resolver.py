"""dkim_resolver + the dkim_ branch of task.resolve_cnames.

WHY THESE TESTS. Asking every selector is ~20 queries a domain, so the module leans on two guard
queries to avoid most of them — and each guard can turn into a silent wrong answer: a prune that
fires on anything other than NXDOMAIN hides real selectors, and a missing wildcard check reports
every platform at once for a zone that answers everything. The rest pins what a hit is, and that
the branch keeps the cname path's guarantee (never retries/, its own dataset).

Run: pytest tests/test_dkim_resolver.py
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import dns.message
import pytest

import dkim_resolver as D

REPO = Path(__file__).resolve().parents[1]
MISS = {"rcode": "NXDOMAIN", "cnames": [], "has_key": False}
EMPTY = {"rcode": "NOERROR", "cnames": [], "has_key": False}
KEY = {"rcode": "NOERROR", "cnames": [], "has_key": True}


def _msg(qname, answer="", rcode="NOERROR"):
    return dns.message.from_text(
        f"id 1\nopcode QUERY\nrcode {rcode}\nflags QR RD RA\n;QUESTION\n{qname} IN TXT\n;ANSWER\n{answer}")


def _fake(answers, calls, default=MISS):
    async def lookup(name, ns, timeout):
        calls.append(name)
        v = answers.get(name, default)
        return v.pop(0) if isinstance(v, list) else v
    return lookup


def _run(domains, answers, calls=None, default=MISS, **kw):
    calls = [] if calls is None else calls
    kw.setdefault("selectors", ("k2", "s1", "pm"))
    return asyncio.run(D.resolve_domains(domains, qps=10000, lookup=_fake(answers, calls, default), **kw))


# ------------------------------------------------------------------ parsing
def test_a_delegated_key_keeps_the_vendor_chain():
    r = D.parse_selector(_msg("k2._domainkey.acme.com.",
                              "k2._domainkey.acme.com. 300 IN CNAME dkim2.MCSV.net.\n"
                              'dkim2.mcsv.net. 300 IN TXT "v=DKIM1; k=rsa; p=MIGfMA0G" "CSqGSIb3"\n'))
    assert r == {"rcode": "NOERROR", "cnames": ["dkim2.mcsv.net"], "has_key": True}


def test_a_cname_whose_target_has_no_key_is_still_a_delegation():
    r = D.parse_selector(_msg("s1._domainkey.acme.com.",
                              "s1._domainkey.acme.com. 300 IN CNAME s1.domainkey.u1.wl.sendgrid.net.\n"))
    assert r["cnames"] == ["s1.domainkey.u1.wl.sendgrid.net"] and r["has_key"] is False


def test_a_revoked_key_is_still_a_key_record_and_other_txt_is_not():
    assert D.parse_selector(_msg("pm._domainkey.a.com.", 'pm._domainkey.a.com. 60 IN TXT "v=DKIM1; p="\n'))["has_key"]
    assert not D.parse_selector(_msg("pm._domainkey.a.com.", 'pm._domainkey.a.com. 60 IN TXT "hello"\n'))["has_key"]


# ------------------------------------------------------------------ the guards
def test_nxdomain_at_domainkey_prunes_every_selector():
    calls = []
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": MISS}, calls)
    assert calls == ["_domainkey.acme.com"]
    assert (row["pruned"], row["domainkey_rcode"], row["selectors_asked"], row["queries"]) == (True, "NXDOMAIN", 0, 1)


@pytest.mark.parametrize("base", [EMPTY, {"rcode": "SERVFAIL", "cnames": [], "has_key": False},
                                  {"rcode": "TIMEOUT", "cnames": [], "has_key": False}])
def test_only_nxdomain_prunes(base, monkeypatch):
    """NODATA is the RFC 8020 answer for "children exist". A failed lookup proves nothing."""
    async def no_sleep(_):
        return None
    monkeypatch.setattr(D.asyncio, "sleep", no_sleep)
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": base, "k2._domainkey.acme.com": KEY})
    assert row["pruned"] is False and [h["selector"] for h in row["hits"]] == ["k2"]


def test_full_mode_asks_every_selector_without_the_prune():
    calls = []
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": MISS, "s1._domainkey.acme.com": KEY}, calls, prune=False)
    assert "_domainkey.acme.com" not in calls and row["domainkey_rcode"] == "NOT_ASKED"
    assert row["selectors_asked"] == 3 and [h["selector"] for h in row["hits"]] == ["s1"]


def test_a_wildcard_zone_is_marked_and_no_selector_is_reported():
    calls = []
    wild = {"rcode": "NOERROR", "cnames": ["parking.example.net"], "has_key": False}
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": EMPTY}, calls, default=wild)
    assert row["wildcard"] is True and row["hits"] == [] and row["selectors_asked"] == 0
    assert calls == ["_domainkey.acme.com", f"{D.WILDCARD_PROBE}._domainkey.acme.com"]


# ------------------------------------------------------------------ hits
def test_hits_keep_selector_chain_and_key_and_skip_empty_answers():
    (row,) = _run(["acme.com"], {
        "_domainkey.acme.com": EMPTY,
        "k2._domainkey.acme.com": {"rcode": "NOERROR", "cnames": ["dkim2.mcsv.net"], "has_key": True},
        "s1._domainkey.acme.com": EMPTY,                    # NODATA: the name exists, nothing there
        "pm._domainkey.acme.com": KEY})
    assert row["hits"] == [{"selector": "k2", "cnames": ["dkim2.mcsv.net"], "has_key": True},
                           {"selector": "pm", "cnames": [], "has_key": True}]
    assert (row["selectors_asked"], row["selectors_failed"], row["queries"]) == (3, 0, 5)


def test_a_failed_selector_lookup_is_counted_not_read_as_absent(monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr(D.asyncio, "sleep", no_sleep)
    calls = []
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": EMPTY,
                                 "s1._domainkey.acme.com": {"rcode": "TIMEOUT", "cnames": [], "has_key": False}},
                  calls, retries=1)
    assert row["selectors_failed"] == 1 and calls.count("s1._domainkey.acme.com") == 2


def test_to_table_matches_the_schema():
    rows = _run(["acme.com"], {"_domainkey.acme.com": EMPTY, "k2._domainkey.acme.com": KEY})
    t = D.to_table(rows, source_file="dkim_r1_00001.txt", worker="contabo54")
    assert t.schema.equals(D.SCHEMA) and t.column("hits")[0].as_py()[0]["selector"] == "k2"


def test_selectors_are_unique_and_the_probe_is_not_one_of_them():
    assert len(set(D.SELECTORS)) == len(D.SELECTORS) and D.WILDCARD_PROBE not in D.SELECTORS


def test_the_mailbox_provider_selectors_are_asked():
    """centralake resolve_dkim.N_SELECTORS mirrors len(SELECTORS); change both together."""
    assert {"selector1", "selector2", "google"} <= set(D.SELECTORS) and len(D.SELECTORS) == 20


# ------------------------------------------------------------------ the path
def test_file_prefixes():
    assert D.is_dkim_file("dkim_20261012_00001.txt") and D.prunes("dkim_20261012_00001.txt")
    assert D.is_dkim_file("dkimfull_canary_00001.txt") and not D.prunes("dkimfull_canary_00001.txt")
    assert not D.is_dkim_file("mail_20261012_00001.txt") and not D.is_dkim_file("cname_x_1.txt")


def test_dataset_name_cannot_merge_into_an_existing_dataset():
    assert D.DATASET == "dkim_resolution" and "subdomains" not in D.DATASET


def test_the_dkim_branch_stays_on_the_cname_path():
    src = (REPO / "task.py").read_text(encoding="utf-8")
    body = src.split("def _resolve_dkim(")[1].split("\n@app.task")[0]
    assert "dataset=dkim_resolver.DATASET" in body and "CNAME_DONE_FOLDER" in body
    assert "move_to_retries" not in body
    task = src.split('name="task.resolve_cnames"')[1].split("except BaseException")[0]
    assert "return _resolve_dkim(input_path, filename)" in task
