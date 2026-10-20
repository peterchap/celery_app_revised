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


def test_a_delegation_whose_target_does_not_exist_yet_is_a_hit():
    """M365's standby selector2: the CNAME is published, the tenant-side name is NXDOMAIN until
    the key rotates. The resolver returns the chain WITH rcode NXDOMAIN; it is still a hit."""
    standby = "selector2-acme-com._domainkey.acme.onmicrosoft.com"
    r = D.parse_selector(_msg("selector2._domainkey.acme.com.",
                              f"selector2._domainkey.acme.com. 3600 IN CNAME {standby}.\n", rcode="NXDOMAIN"))
    assert r == {"rcode": "NXDOMAIN", "cnames": [standby], "has_key": False}
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": EMPTY, "s1._domainkey.acme.com": r})
    assert row["hits"] == [{"selector": "s1", "cnames": [standby], "has_key": False}]
    assert row["selectors_failed"] == 0


def test_a_bare_nxdomain_or_a_failed_lookup_with_a_chain_is_not_a_hit(monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr(D.asyncio, "sleep", no_sleep)
    (row,) = _run(["acme.com"], {
        "_domainkey.acme.com": EMPTY,
        "k2._domainkey.acme.com": MISS,
        "s1._domainkey.acme.com": {"rcode": "SERVFAIL", "cnames": ["s1.domainkey.u1.wl.sendgrid.net"],
                                   "has_key": False}}, retries=0)
    assert row["hits"] == [] and row["selectors_failed"] == 1


def test_a_wildcard_cname_to_a_missing_target_still_marks_the_zone():
    """`*._domainkey` CNAMEd to a name that does not exist answers NXDOMAIN with a chain for
    every selector, the impossible one included: wildcard, as before."""
    wild = {"rcode": "NXDOMAIN", "cnames": ["nothing.example.net"], "has_key": False}
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": EMPTY}, default=wild)
    assert row["wildcard"] is True and row["hits"] == [] and row["selectors_asked"] == 0


def test_a_failed_selector_lookup_is_counted_not_read_as_absent(monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr(D.asyncio, "sleep", no_sleep)
    calls = []
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": EMPTY,
                                 "s1._domainkey.acme.com": {"rcode": "TIMEOUT", "cnames": [], "has_key": False}},
                  calls, retries=1)
    assert row["selectors_failed"] == 1 and calls.count("s1._domainkey.acme.com") == 2


# ------------------------------------------------------------------ never an absence
@pytest.mark.parametrize("answers,default,kw,expected", [
    ({"_domainkey.acme.com": EMPTY, "k2._domainkey.acme.com": KEY}, MISS, {}, "visible"),
    ({"_domainkey.acme.com": EMPTY}, MISS, {}, "not_visible"),
    ({"_domainkey.acme.com": MISS}, MISS, {}, "not_visible_pruned"),
    ({"_domainkey.acme.com": EMPTY}, {"rcode": "NOERROR", "cnames": ["x.example.net"], "has_key": False},
     {}, "unknown_wildcard"),
    ({"_domainkey.acme.com": EMPTY, "s1._domainkey.acme.com": {"rcode": "TIMEOUT", "cnames": [], "has_key": False}},
     MISS, {"retries": 0}, "unknown_failed"),
])
def test_every_row_says_what_was_visible_and_none_says_absent(answers, default, kw, expected):
    (row,) = _run(["acme.com"], answers, default=default, **kw)
    assert row["dkim_visibility"] == expected


def test_no_visibility_value_reads_as_an_absence():
    """PC's rule: selectors cannot be enumerated, so the vocabulary has no "missing"/"none"."""
    src = (REPO / "dkim_resolver.py").read_text(encoding="utf-8")
    body = src.split("def visibility(")[1].split("\nasync def ")[0]
    values = {line.split('"')[1] for line in body.splitlines() if line.strip().startswith("return \"")}
    assert values == {"visible", "not_visible", "not_visible_pruned", "unknown_wildcard", "unknown_failed"}
    assert not any(w in v for v in values for w in ("missing", "absent", "none", "no_dkim", "no_key"))


def test_selectors_probed_names_exactly_what_was_asked():
    """A trimmed list must not read as "asked and silent" for the names no longer asked."""
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": EMPTY}, selectors=("k2", "s1"))
    assert row["selectors_probed"] == ["k2", "s1"] and row["selectors_asked"] == 2
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": MISS})
    assert row["selectors_probed"] == []


# ------------------------------------------------------------------ previously seen selectors
def test_a_carried_selector_is_asked_even_when_trimmed_from_the_list():
    calls = []
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": EMPTY, "mesmtp._domainkey.acme.com": KEY}, calls,
                  carried={"acme.com": ("mesmtp",)})
    assert row["selectors_probed"] == ["mesmtp", "k2", "s1", "pm"]
    assert [h["selector"] for h in row["hits"]] == ["mesmtp"] and row["stale"] == []


def test_a_carried_selector_that_misses_is_stale_not_dropped():
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": EMPTY}, carried={"acme.com": ("k2", "mesmtp")})
    assert row["carried"] == ["k2", "mesmtp"] and row["stale"] == ["k2", "mesmtp"]
    assert row["dkim_visibility"] == "not_visible"
    # a carried selector is asked once, not again from the common list
    assert row["selectors_probed"] == ["k2", "mesmtp", "s1", "pm"]


def test_a_carried_selector_whose_lookup_failed_is_neither_hit_nor_stale(monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr(D.asyncio, "sleep", no_sleep)
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": EMPTY,
                                 "k2._domainkey.acme.com": {"rcode": "SERVFAIL", "cnames": [], "has_key": False}},
                  carried={"acme.com": ("k2",)}, retries=0)
    assert row["stale"] == [] and row["selectors_failed"] == 1 and row["dkim_visibility"] == "unknown_failed"


def test_the_prune_does_not_skip_carried_selectors_and_a_hit_disproves_it():
    """8.7% of pruned rows sampled 2026-10-16 had a key under an NXDOMAIN _domainkey."""
    calls = []
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": MISS, "selector1._domainkey.acme.com": KEY}, calls,
                  carried={"acme.com": ("selector1",)})
    assert row["pruned"] is False and row["domainkey_rcode"] == "NXDOMAIN"
    assert row["selectors_probed"] == ["selector1", "k2", "s1", "pm"]       # the full list after all
    assert row["dkim_visibility"] == "visible"


def test_a_pruned_domain_asks_only_its_carried_selectors_when_they_miss():
    calls = []
    (row,) = _run(["acme.com"], {"_domainkey.acme.com": MISS}, calls, carried={"acme.com": ("selector1",)})
    assert calls == ["_domainkey.acme.com", f"{D.WILDCARD_PROBE}._domainkey.acme.com",
                     "selector1._domainkey.acme.com"]
    assert row["pruned"] is True and row["stale"] == ["selector1"]
    assert row["dkim_visibility"] == "not_visible_pruned"


def test_a_pruned_domain_with_nothing_carried_costs_one_query_as_before():
    calls = []
    rows = _run(["acme.com", "beta.com"], {"_domainkey.acme.com": MISS, "_domainkey.beta.com": MISS}, calls,
                carried={"beta.com": ()})
    assert [r["queries"] for r in rows] == [1, 1]
    assert sorted(calls) == ["_domainkey.acme.com", "_domainkey.beta.com"]


def test_read_domains_accepts_bare_and_carrying_lines(tmp_path):
    p = tmp_path / "dkim_r1_00001.txt"
    p.write_text("# header\nAcme.com.\nbeta.com k2,Selector1\n\nbeta.com s1 k2\n"
                 f"gamma.com bad/name {D.WILDCARD_PROBE} ok_1\n", encoding="utf-8")
    domains, carried = D.read_domains(p)
    assert domains == ["acme.com", "beta.com", "gamma.com"]
    assert carried == {"beta.com": ("k2", "selector1", "s1"), "gamma.com": ("ok_1",)}


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


def test_selectors_come_from_the_knowledge_snapshot_unchanged():
    """The list moved to dnsproject knowledge/dkim_selectors.yaml (2026-10-17). The corpus probe
    it yields must be the 20 selectors, in query order, that were hard-coded here before."""
    import json
    assert D.SELECTORS == (
        "s1", "s2", "k1", "pic", "k2", "k3", "mte1", "mte2", "resend", "rwmt1", "rwmt2",
        "api", "mail", "litesrv", "ml", "kl", "mailjet", "selector1", "selector2", "google")
    assert D.WILDCARD_PROBE == "dz-wildcard-probe-7q3x"
    snap = json.loads(D._KNOWLEDGE.read_text(encoding="utf-8"))
    assert snap["_generated"]["source"] == "dnsproject/knowledge/dkim_selectors.yaml"
