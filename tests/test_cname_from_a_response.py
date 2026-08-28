"""The CNAME is already in the A response; these tests pin that we keep it, for free.

WHY THIS EXISTS. `gold.dns_wide.cname_record` measured 0.00% across 395.9M rows, and the
cause was not a missing lookup. `dns_lookup` has no `lookup_cname` and never needed one:
the resolver follows the alias for us, so the CNAME rrset arrives in the SAME response as
the address records. Iterating a dnspython `Answer` yields only `answer.rrset` — the final
address rrset — so `_do_lookup` was dropping an alias it already held, on every A query in
the estate.

The invariant that matters is not "cname is populated", it is **"cname costs no query"**.
A fix that reintroduced a CNAME lookup would fill the column and add 395M queries per
crawl, which is why `test_peek_cname_never_queries` and the query-count assertion in
`test_a_lookup_harvests_cname_without_extra_query` are the load-bearing tests here.

Apex CNAME is deliberately NOT expected to be populated: a CNAME cannot legally coexist
with the SOA and NS an apex must have. www_cname is the leg that carries the signal.

Run: pytest tests/test_cname_from_a_response.py
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _import_dns_lookup():
    """Import dns_module.dns_lookup, stubbing lmdb if the env is lean.

    lmdb is a production dependency but not needed by anything under test — every
    LMDB path no-ops when `_lmdb_env is None`. Stubbing it lets these run in a CI env
    without the C extension rather than skipping, which is how a test stops earning
    its keep.
    """
    if "lmdb" not in sys.modules:
        try:
            import lmdb  # noqa: F401
        except ModuleNotFoundError:
            stub = types.ModuleType("lmdb")
            stub.MapResizedError = type("MapResizedError", (Exception,), {})
            stub.MapFullError = type("MapFullError", (Exception,), {})
            stub.Error = type("Error", (Exception,), {})
            sys.modules["lmdb"] = stub
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    import dns_module.dns_lookup as m
    return m


m = _import_dns_lookup()
import dns.rdatatype


# --------------------------------------------------------------------------- stubs
class _Rdata:
    def __init__(self, address=None, target=None):
        self.address = address
        self.target = target


class _RRset:
    def __init__(self, name, rdtype, rdatas, ttl=300):
        self.name = name
        self.rdtype = rdtype
        self.ttl = ttl
        self._rdatas = rdatas

    def __iter__(self):
        return iter(self._rdatas)


class _Response:
    def __init__(self, answer):
        self.answer = answer


class _Answer:
    """Minimal stand-in for dnspython's Answer: iterating yields the FINAL rrset only."""

    def __init__(self, rrsets):
        self.response = _Response(rrsets)
        self.rrset = rrsets[-1]

    def __iter__(self):
        return iter(self.rrset)


def _a_answer_with_cname(qname, chain, addr="1.2.3.4", ttl=300):
    """Build an A answer whose response carries `chain` as CNAME hops before the A."""
    rrsets = []
    owner = qname
    for target in chain:
        rrsets.append(_RRset(owner, dns.rdatatype.CNAME, [_Rdata(target=target)], ttl))
        owner = target
    rrsets.append(_RRset(owner, dns.rdatatype.A, [_Rdata(address=addr)], ttl))
    return _Answer(rrsets)


@pytest.fixture(autouse=True)
def _clean_caches():
    m._inmem_cache.clear()
    m._inmem_cache_order.clear()
    m._DISABLE_CACHE = None
    yield
    m._inmem_cache.clear()
    m._inmem_cache_order.clear()


# ----------------------------------------------------------------- _extract_cname
def test_extract_returns_first_hop_not_final_name():
    """For a -> b -> c we want b: what this name points at, not where the chain ends.

    `answer.canonical_name` would give c, which answers a different question than the
    column's name implies — the trap `soa_record` already fell into by holding only MNAME.
    """
    ans = _a_answer_with_cname("shop.example.com", ["edge.cdn.net", "origin.cdn.net"])
    assert m._extract_cname(ans, "shop.example.com") == "edge.cdn.net"


def test_extract_is_case_and_trailing_dot_insensitive():
    ans = _a_answer_with_cname("Shop.Example.COM.", ["Edge.CDN.net."])
    assert m._extract_cname(ans, "shop.example.com") == "edge.cdn.net"


def test_extract_returns_none_when_not_aliased():
    ans = _Answer([_RRset("plain.example.com", dns.rdatatype.A, [_Rdata(address="1.2.3.4")])])
    assert m._extract_cname(ans, "plain.example.com") is None


def test_extract_ignores_cname_owned_by_another_name():
    """Only the hop whose owner IS the queried name is this name's alias."""
    rrsets = [
        _RRset("other.example.com", dns.rdatatype.CNAME, [_Rdata(target="elsewhere.net")]),
        _RRset("plain.example.com", dns.rdatatype.A, [_Rdata(address="1.2.3.4")]),
    ]
    assert m._extract_cname(_Answer(rrsets), "plain.example.com") is None


def test_extract_survives_a_malformed_answer():
    assert m._extract_cname(object(), "x.example.com") is None
    assert m._extract_cname(None, "x.example.com") is None


# --------------------------------------------------------------------- peek_cname
def test_peek_returns_empty_when_nothing_cached():
    assert asyncio.run(m.peek_cname("never-seen.example.com")) == ""


def test_peek_reads_what_the_a_lookup_left():
    m._put_in_inmem_cache(m._cache_key("CNAME", "www.example.com"), "NOERROR", ["edge.cdn.net"], 300)
    assert asyncio.run(m.peek_cname("www.example.com")) == "edge.cdn.net"


def test_peek_treats_a_negative_entry_as_empty():
    m._put_in_inmem_cache(m._cache_key("CNAME", "www.example.com"), "NXDOMAIN", [], 300)
    assert asyncio.run(m.peek_cname("www.example.com")) == ""


def test_peek_cname_never_queries(monkeypatch):
    """The load-bearing one. peek_cname must not fall through to a live lookup.

    Using perform_lookup('CNAME', ...) here would look identical in a cache-warm test and
    add one query per domain per crawl in production — 395M of them.
    """
    calls = []

    async def _boom(*a, **kw):
        calls.append(a)
        raise AssertionError("peek_cname issued a DNS query")

    monkeypatch.setattr(m, "_do_lookup", _boom)
    monkeypatch.setattr(m, "perform_lookup", _boom)
    assert asyncio.run(m.peek_cname("cold.example.com")) == ""
    assert calls == []


def test_peek_skips_lmdb_when_asked(monkeypatch):
    """The apex path passes use_lmdb=False, and that must actually skip the read.

    An apex is ~never aliased, so the LMDB fallback there is a guaranteed miss that still
    costs a semaphore and a thread hop — once per domain, 395M times per crawl.
    """
    reads = []

    async def _counting_read(key):
        reads.append(key)
        return None

    monkeypatch.setattr(m, "_read_from_lmdb", _counting_read)

    assert asyncio.run(m.peek_cname("example.com", use_lmdb=False)) == ""
    assert reads == []

    # ...and the default still consults it, for the www path where it earns its keep.
    assert asyncio.run(m.peek_cname("www.example.com")) == ""
    assert reads == [m._cache_key("CNAME", "www.example.com")]


def test_peek_without_lmdb_still_sees_this_process(monkeypatch):
    """in-memory only is not "off": an apex that really does answer CNAME is still caught."""
    async def _never(key):
        raise AssertionError("LMDB consulted with use_lmdb=False")

    monkeypatch.setattr(m, "_read_from_lmdb", _never)
    m._put_in_inmem_cache(m._cache_key("CNAME", "odd-apex.example"), "NOERROR", ["host.cdn.net"], 300)
    assert asyncio.run(m.peek_cname("odd-apex.example", use_lmdb=False)) == "host.cdn.net"


# ------------------------------------------------------- the round trip, and its cost
def test_a_lookup_harvests_cname_without_extra_query(monkeypatch):
    queries = []

    class _Resolver:
        async def resolve(self, name, rdtype):
            queries.append((name, rdtype))
            return _a_answer_with_cname(name, ["edge.cdn.net"])

    monkeypatch.setattr(m.CONFIG, "enable_global_rate_limit", False, raising=False)

    async def _run():
        rcode, answers, ttl = await m._do_lookup(
            "A", "www.example.com", _Resolver(), asyncio.Semaphore(1)
        )
        assert (rcode, answers) == ("NOERROR", ["1.2.3.4"])
        return await m.peek_cname("www.example.com")

    assert asyncio.run(_run()) == "edge.cdn.net"
    # One A query. Not two.
    assert queries == [("www.example.com", dns.rdatatype.A)]


def test_unaliased_name_caches_nothing(monkeypatch):
    """No alias must leave no entry — not an empty-string entry that reads as a measurement."""
    class _Resolver:
        async def resolve(self, name, rdtype):
            return _Answer([_RRset(name, dns.rdatatype.A, [_Rdata(address="1.2.3.4")])])

    monkeypatch.setattr(m.CONFIG, "enable_global_rate_limit", False, raising=False)

    async def _run():
        await m._do_lookup("A", "plain.example.com", _Resolver(), asyncio.Semaphore(1))
        return m._get_from_inmem_cache(m._cache_key("CNAME", "plain.example.com"))

    assert asyncio.run(_run()) is None


def test_aaaa_does_not_overwrite_the_a_harvest(monkeypatch):
    """AAAA carries the same chain; harvesting it twice would race for no gain."""
    class _Resolver:
        async def resolve(self, name, rdtype):
            return _a_answer_with_cname(name, ["v6.cdn.net"], addr="::1")

    monkeypatch.setattr(m.CONFIG, "enable_global_rate_limit", False, raising=False)
    m._put_in_inmem_cache(m._cache_key("CNAME", "www.example.com"), "NOERROR", ["edge.cdn.net"], 300)

    async def _run():
        await m._do_lookup("AAAA", "www.example.com", _Resolver(), asyncio.Semaphore(1))
        return await m.peek_cname("www.example.com")

    assert asyncio.run(_run()) == "edge.cdn.net"
