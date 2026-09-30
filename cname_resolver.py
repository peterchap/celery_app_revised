"""CNAME + A resolution for the separate cname_queue path. Not DNSApplication, and nothing to the lake.

WHY THIS EXISTS. Identity / ERP / portal SaaS (Okta, Auth0, Clerk, WorkOS, Zendesk, Freshworks, …)
is reached through a customer SUBDOMAIN CNAMEd to the platform (login.acme.com -> acme.okta.com).
Certstream has already seen those hostnames, and the lake never resolves them. This resolves one
host list: one A query per host, whose answer carries the whole CNAME chain. There are no
NS/MX/TXT/SOA/cert/SMTP probes, no LMDB and no dns_expanded. Design:
datazag-pipeline/work/subdomain-cname-worker-path.md.

The results go to the master as Flight dataset `cname_resolution`. The master lands them at
r2://domains-monitor/cname_resolution/, outside DuckLake and the compactor
(master_flight_server.py).

Everything asyncio (resolver use, semaphore, rate limiter) is created INSIDE the coroutine.
loop_guard.run_coroutine gives each task a fresh event loop, and asyncio primitives bind to the
loop they were first used on. This is also why dns_module's module-global TokenBucket is not
reused here.
"""
from __future__ import annotations

import asyncio
import socket
import time
from datetime import datetime, timezone

import pyarrow as pa

DATASET = "cname_resolution"
SCHEMA = pa.schema([
    ("host", pa.string()),
    ("rcode", pa.string()),
    ("cnames", pa.list_(pa.string())),
    ("a", pa.list_(pa.string())),
    ("min_ttl", pa.int32()),
    ("resolved_at", pa.timestamp("s", tz="UTC")),
    ("attempts", pa.int16()),
    ("worker", pa.string()),
    ("source_file", pa.string()),
])
TRANSIENT = ("SERVFAIL", "TIMEOUT", "ERROR")


class RateLimiter:
    """One rate for the whole task: the next query may start `interval` after the last one."""

    def __init__(self, qps: float):
        self.interval = 1.0 / qps
        self.next_at = 0.0
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            now = time.monotonic()
            if self.next_at > now:
                await asyncio.sleep(self.next_at - now)
            self.next_at = max(now, self.next_at) + self.interval


def parse_response(response) -> dict:
    """rcode, CNAME chain (answer order, owner -> target) and A records from a dnspython Message."""
    import dns.rcode
    import dns.rdatatype

    chain, addrs, ttls = [], [], []
    for rrset in response.answer:
        ttls.append(rrset.ttl)
        if rrset.rdtype == dns.rdatatype.CNAME:
            chain += [rd.target.to_text().rstrip(".").lower() for rd in rrset]
        elif rrset.rdtype == dns.rdatatype.A:
            addrs += [rd.to_text() for rd in rrset]
    return {"rcode": dns.rcode.to_text(response.rcode()), "cnames": chain, "a": sorted(addrs),
            "min_ttl": min(ttls) if ttls else None}


async def query_a(host: str, nameserver: str, timeout: float) -> dict:
    import dns.asyncquery
    import dns.exception
    import dns.flags
    import dns.message

    q = dns.message.make_query(host, "A")
    try:
        r = await dns.asyncquery.udp(q, nameserver, timeout=timeout)
        if r.flags & dns.flags.TC:
            r = await dns.asyncquery.tcp(q, nameserver, timeout=timeout)
    except dns.exception.Timeout:
        return {"rcode": "TIMEOUT", "cnames": [], "a": [], "min_ttl": None}
    except Exception:  # network errors, malformed responses
        return {"rcode": "ERROR", "cnames": [], "a": [], "min_ttl": None}
    return parse_response(r)


async def resolve_hosts(hosts: list[str], *, qps: float, nameserver: str = "127.0.0.1",
                        timeout: float = 4.0, retries: int = 2, parallel: int = 64,
                        query=query_a) -> list[dict]:
    """Resolve every host at `qps`. SERVFAIL / timeout / error are retried and then kept as their
    own rcode: never folded into NXDOMAIN, and never dropped. `query` is injectable for tests."""
    limiter = RateLimiter(qps)
    sem = asyncio.Semaphore(parallel)

    async def one(host: str) -> dict:
        async with sem:
            res, attempts = None, 0
            for attempt in range(retries + 1):
                attempts += 1
                await limiter.wait()
                res = await query(host, nameserver, timeout)
                if res["rcode"] not in TRANSIENT:
                    break
                await asyncio.sleep(1.0 * (attempt + 1))
        return {**res, "host": host, "attempts": attempts,
                "resolved_at": datetime.now(timezone.utc).replace(microsecond=0)}

    return await asyncio.gather(*(one(h) for h in hosts))


def read_hosts(path) -> list[str]:
    """One host per line; blanks, comments and duplicates dropped, lowercased, trailing dot removed."""
    seen, out = set(), []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            h = line.strip().lower().rstrip(".")
            if h and not h.startswith("#") and h not in seen:
                seen.add(h)
                out.append(h)
    return out


def to_table(rows: list[dict], source_file: str, worker: str | None = None) -> pa.Table:
    worker = worker or socket.gethostname()
    return pa.Table.from_pylist(
        [{"host": r["host"], "rcode": r["rcode"], "cnames": r["cnames"], "a": r["a"],
          "min_ttl": r["min_ttl"], "resolved_at": r["resolved_at"], "attempts": r["attempts"],
          "worker": worker, "source_file": source_file} for r in rows],
        schema=SCHEMA)
