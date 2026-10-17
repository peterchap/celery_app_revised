"""DKIM selector probing on the cname_queue path: which sending platforms a domain has set up.

WHY THIS EXISTS. mail_resolver finds sending infrastructure on subdomains, but only on hosts that
Certificate Transparency happens to name — and whether a platform's hosts get certificates is a
property of the platform, not of its market share (Mailgun's `email.<domain>` hosts do; most
others' do not). DKIM does not have that bias. A domain that sends through a platform publishes
that platform's key under a selector the PLATFORM names: `k2._domainkey.<domain>` CNAMEd to
dkim.mcsv.net is Mailchimp whether or not any certificate was ever issued. So for a list of
domains this asks for a fixed set of well-known selectors and records what answers.

It rides the cname_queue path exactly as mail_resolver does: same drop folder, same dedicated
workers, same state folders, never retries/. A file named `dkim_<run>_<n>.txt` (one DOMAIN per
line) is resolved here, and the rows go to Flight dataset `dkim_resolution`, which the master
lands at r2://domains-monitor/dkim_resolution/. ⚠ The master's sink branch must be live BEFORE a
worker sends this dataset: do_put stages a dataset it does not recognise into bronze.

WHAT A ROW IS. One row per domain ASKED, with the selectors that answered in `hits`. Each hit
keeps the CNAME chain (the vendor's host, when the key is delegated) and whether a key record
came back. This module records and does not interpret: which vendor a target belongs to is the
consumer's mapping. Two things it cannot see, by construction:
  * selectors that carry an account id (SMTP2GO s<id>, HubSpot hs1-<id>, Amazon SES tokens,
    Constant Contact numeric ids) — there is nothing fixed to ask for;
  * a platform whose key was pasted as a TXT under a generic selector name. The selector NAME is
    then the only clue, and several names are shared between vendors (`k1`, `mail`, `api`).
So "no hit" is never "does not use a sending platform".

QUERY BUDGET — the reason for the two guard queries. Asking every selector costs len(SELECTORS)
queries per domain. Two cheap questions avoid most of that:
  1. `_domainkey.<domain>`. NXDOMAIN there means nothing exists beneath it (RFC 8020), so no
     selector can answer and none is asked (`pruned`). ⚠ Not every authoritative server honours
     RFC 8020; a few answer NXDOMAIN for an empty non-terminal that does have children. A file
     named `dkimfull_...` skips this guard, which is how the loss is measured.
  2. A selector that cannot exist (`WILDCARD_PROBE`). If THAT answers, the zone has a wildcard and
     every selector would "hit"; the domain is marked `wildcard` and no selector is asked.

As in cname_resolver, every asyncio primitive is created inside the coroutine.
"""
from __future__ import annotations

import asyncio
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa

from cname_resolver import RateLimiter, TRANSIENT

DATASET = "dkim_resolution"
FILE_PREFIX = "dkim_"
FULL_PREFIX = "dkimfull_"          # no RFC 8020 prune: every selector is asked

# The selector list is authored ONCE, in dnsproject knowledge/dkim_selectors.yaml, and arrives
# here as a generated snapshot (knowledge/dkim_selectors.json; regenerate with dnsproject
# scripts/export_knowledge.py). SELECTORS is its `corpus_probe` subset, in the file's order,
# which is the order they are asked in. Adding one costs a query per un-pruned domain per run:
# the YAML carries why each is in, and the measured hits of the ten retired on 2026-10-13.
_KNOWLEDGE = Path(__file__).resolve().parent / "knowledge" / "dkim_selectors.json"


def _load_selectors(path: Path = _KNOWLEDGE) -> tuple[tuple[str, ...], str]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return (tuple(s["name"] for s in doc["selectors"] if s["corpus_probe"]),
            doc["wildcard_probe"])


SELECTORS, WILDCARD_PROBE = _load_selectors()

HIT = pa.struct([("selector", pa.string()), ("cnames", pa.list_(pa.string())), ("has_key", pa.bool_())])
SCHEMA = pa.schema([
    ("domain", pa.string()),
    ("domainkey_rcode", pa.string()),   # of `_domainkey.<domain>`; NOT_ASKED in dkimfull_ mode
    ("pruned", pa.bool_()),             # _domainkey was NXDOMAIN, so no selector was asked
    ("wildcard", pa.bool_()),           # the impossible selector answered; hits would be meaningless
    ("selectors_asked", pa.int16()),
    ("selectors_failed", pa.int16()),   # selectors whose lookup ended TIMEOUT / SERVFAIL / ERROR
    ("hits", pa.list_(HIT)),
    ("resolved_at", pa.timestamp("s", tz="UTC")),
    ("queries", pa.int16()),
    ("worker", pa.string()),
    ("source_file", pa.string()),
])


def is_dkim_file(filename: str) -> bool:
    return filename.startswith((FILE_PREFIX, FULL_PREFIX))


def prunes(filename: str) -> bool:
    return not filename.startswith(FULL_PREFIX)


def parse_selector(response) -> dict:
    """rcode, CNAME chain and whether a DKIM key record came back, from one TXT answer.

    `has_key` is true for a TXT that carries a `p=` tag, INCLUDING an empty one: `p=` with no
    value is a revoked key, and a revoked key is still a selector the domain set up. Whether
    it is live is not judged here.
    """
    import dns.rcode
    import dns.rdatatype

    chain, has_key = [], False
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            chain += [rd.target.to_text().rstrip(".").lower() for rd in rrset]
        elif rrset.rdtype == dns.rdatatype.TXT:
            for rd in rrset:
                txt = b"".join(rd.strings).decode("utf-8", "replace").replace(" ", "").lower()
                if "p=" in txt:
                    has_key = True
    return {"rcode": dns.rcode.to_text(response.rcode()), "cnames": chain, "has_key": has_key}


async def lookup(name: str, nameserver: str, timeout: float) -> dict:
    """One TXT query, parsed. A transport failure is its own rcode, never an empty answer."""
    import dns.asyncquery
    import dns.exception
    import dns.flags
    import dns.message

    q = dns.message.make_query(name, "TXT")
    try:
        r = await dns.asyncquery.udp(q, nameserver, timeout=timeout)
        if r.flags & dns.flags.TC:
            r = await dns.asyncquery.tcp(q, nameserver, timeout=timeout)
    except dns.exception.Timeout:
        return {"rcode": "TIMEOUT", "cnames": [], "has_key": False}
    except Exception:  # network errors, malformed responses
        return {"rcode": "ERROR", "cnames": [], "has_key": False}
    return parse_selector(r)


def _answered(res: dict) -> bool:
    return res["rcode"] == "NOERROR" and bool(res["cnames"] or res["has_key"])


async def resolve_domains(domains: list[str], *, qps: float, prune: bool = True,
                          nameserver: str = "127.0.0.1", timeout: float = 4.0, retries: int = 1,
                          parallel: int = 64, selectors: tuple = SELECTORS, lookup=lookup) -> list[dict]:
    """Probe every domain at `qps` (one limiter across all queries). `lookup` is injectable."""
    limiter = RateLimiter(qps)
    sem = asyncio.Semaphore(parallel)

    async def ask(name: str) -> tuple[dict, int]:
        res, sent = None, 0
        for attempt in range(retries + 1):
            sent += 1
            await limiter.wait()
            res = await lookup(name, nameserver, timeout)
            if res["rcode"] not in TRANSIENT:
                break
            await asyncio.sleep(1.0 * (attempt + 1))
        return res, sent

    async def one(domain: str) -> dict:
        row = {"domain": domain, "domainkey_rcode": "NOT_ASKED", "pruned": False, "wildcard": False,
               "selectors_asked": 0, "selectors_failed": 0, "hits": [], "queries": 0}
        async with sem:
            if prune:
                base, n = await ask(f"_domainkey.{domain}")
                row["queries"] += n
                row["domainkey_rcode"] = base["rcode"]
                if base["rcode"] == "NXDOMAIN":
                    row["pruned"] = True
            if not row["pruned"]:
                probe, n = await ask(f"{WILDCARD_PROBE}._domainkey.{domain}")
                row["queries"] += n
                if _answered(probe):
                    row["wildcard"] = True
                else:
                    for sel in selectors:
                        res, n = await ask(f"{sel}._domainkey.{domain}")
                        row["queries"] += n
                        row["selectors_asked"] += 1
                        if res["rcode"] in TRANSIENT:
                            row["selectors_failed"] += 1
                        elif _answered(res):
                            row["hits"].append({"selector": sel, "cnames": res["cnames"],
                                                "has_key": res["has_key"]})
        row["resolved_at"] = datetime.now(timezone.utc).replace(microsecond=0)
        return row

    return await asyncio.gather(*(one(d) for d in domains))


def to_table(rows: list[dict], source_file: str, worker: str | None = None) -> pa.Table:
    worker = worker or socket.gethostname()
    names = [f.name for f in SCHEMA if f.name not in ("worker", "source_file")]
    return pa.Table.from_pylist(
        [{**{k: r[k] for k in names}, "worker": worker, "source_file": source_file} for r in rows],
        schema=SCHEMA)
