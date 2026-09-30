"""cname_resolver + task.resolve_cnames: the separate cname_queue path.

WHY THESE TESTS. The path exists to resolve subdomains WITHOUT entering the lake, and it has one way
to break that silently: a failed file landing in retries/ (or inprogress/). The master's retry sweep
would re-enqueue it onto retry_queue, where it becomes a DNSApplication job and its hosts are written
to dns_expanded. The source check below pins that. The rest pins the resolution semantics the
coverage numbers depend on: the whole CNAME chain is kept, and transient failures are retried and
recorded as themselves rather than dropped or read as NXDOMAIN.

Run: pytest tests/test_cname_resolver.py
"""
from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

import dns.message
import pytest

import cname_resolver as C

REPO = Path(__file__).resolve().parents[1]


def test_read_hosts_normalises_and_dedupes(tmp_path):
    f = tmp_path / "cname_x_00001.txt"
    f.write_text("Login.Acme.com.\n\n# comment\nlogin.acme.com\nsso.beta.io\n", encoding="utf-8")
    assert C.read_hosts(f) == ["login.acme.com", "sso.beta.io"]


def test_parse_response_keeps_the_whole_chain():
    msg = dns.message.from_text("""id 1
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
login.acme.com. IN A
;ANSWER
login.acme.com. 300 IN CNAME acme.customdomains.okta.com.
acme.customdomains.okta.com. 60 IN CNAME ok12-crtrs.oktaedge.okta.com.
ok12-crtrs.oktaedge.okta.com. 30 IN A 3.33.1.1
ok12-crtrs.oktaedge.okta.com. 30 IN A 3.33.1.2
""")
    r = C.parse_response(msg)
    assert r["rcode"] == "NOERROR"
    assert r["cnames"] == ["acme.customdomains.okta.com", "ok12-crtrs.oktaedge.okta.com"]
    assert r["a"] == ["3.33.1.1", "3.33.1.2"]
    assert r["min_ttl"] == 30


def test_transient_failures_are_retried_then_kept_as_themselves():
    calls = {}

    async def fake(host, ns, timeout):
        calls[host] = calls.get(host, 0) + 1
        if host == "flaky.acme.com" and calls[host] < 2:
            return {"rcode": "SERVFAIL", "cnames": [], "a": [], "min_ttl": None}
        if host == "dead.acme.com":
            return {"rcode": "TIMEOUT", "cnames": [], "a": [], "min_ttl": None}
        if host == "gone.acme.com":
            return {"rcode": "NXDOMAIN", "cnames": [], "a": [], "min_ttl": None}
        return {"rcode": "NOERROR", "cnames": ["x.okta.com"], "a": ["1.2.3.4"], "min_ttl": 60}

    async def no_sleep(_):
        return None

    orig = asyncio.sleep
    asyncio.sleep = no_sleep  # retry backoff only; the limiter is measured separately below
    try:
        rows = asyncio.run(C.resolve_hosts(["ok.acme.com", "flaky.acme.com", "dead.acme.com", "gone.acme.com"],
                                           qps=10_000, retries=2, query=fake))
    finally:
        asyncio.sleep = orig
    by = {r["host"]: r for r in rows}
    assert by["ok.acme.com"]["rcode"] == "NOERROR" and by["ok.acme.com"]["attempts"] == 1
    assert by["flaky.acme.com"]["rcode"] == "NOERROR" and by["flaky.acme.com"]["attempts"] == 2
    assert by["dead.acme.com"]["rcode"] == "TIMEOUT" and by["dead.acme.com"]["attempts"] == 3
    assert by["gone.acme.com"]["rcode"] == "NXDOMAIN" and by["gone.acme.com"]["attempts"] == 1
    assert len(rows) == 4, "no host may be dropped"


def test_rate_limit_holds_across_the_task():
    async def fake(host, ns, timeout):
        return {"rcode": "NOERROR", "cnames": [], "a": [], "min_ttl": None}

    t = time.monotonic()
    asyncio.run(C.resolve_hosts([f"h{i}.acme.com" for i in range(21)], qps=20, query=fake))
    # 21 queries at 20 qps: the last may start no earlier than 1.0 s after the first.
    assert time.monotonic() - t >= 0.95


def test_table_schema_is_pinned():
    rows = asyncio.run(C.resolve_hosts(["a.acme.com"], qps=1000,
                                       query=lambda h, n, t: _const({"rcode": "NOERROR", "cnames": [],
                                                                     "a": [], "min_ttl": None})))
    table = C.to_table(rows, source_file="cname_r1_00001.txt", worker="w1")
    assert table.schema == C.SCHEMA
    assert table.num_rows == 1 and table.column("worker")[0].as_py() == "w1"


async def _const(v):
    return v


def test_resolve_cnames_task_never_uses_the_shared_retry_or_inprogress_folders():
    src = (REPO / "task.py").read_text(encoding="utf-8")
    body = src[src.index("def resolve_cnames("):]
    body = body[:body.index("\n@app.task", 1)]
    assert "move_to_retries" not in body and "RETRY_FOLDER" not in body
    assert not re.search(r"\bIN_PROGRESS_FOLDER\b", body), "must use CNAME_IN_PROGRESS_FOLDER only"
    assert "CNAME_FAILED_FOLDER" in body


def test_cname_queue_is_declared_and_routed():
    src = (REPO / "celery_app.py").read_text(encoding="utf-8")
    assert 'Queue("cname_queue"' in src
    assert '"task.resolve_cnames":' in src and '"queue": "cname_queue"' in src
