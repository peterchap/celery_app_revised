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

NEVER AN ABSENCE. Selectors cannot be enumerated from DNS, so no row can say a domain has no DKIM;
it can only say which of the names we asked answered. `dkim_visibility` spells that out, and none
of its values is an absence:
  visible             at least one selector answered (zone not a wildcard);
  not_visible         selectors were asked and none answered — the key, if any, is under a name
                      we did not ask;
  not_visible_pruned  `_domainkey` was NXDOMAIN so the common list was not asked (guard 1 below,
                      which some servers get wrong);
  unknown_wildcard    the zone answers every selector, so nothing can be read from it;
  unknown_failed      no answer, and at least one lookup ended TIMEOUT / SERVFAIL / ERROR.
`selectors_probed` lists exactly which names were asked, so a consumer can tell "not asked this
time" (the list was trimmed, or the guard fired) from "asked and silent".

PREVIOUSLY SEEN SELECTORS. A row is one probe, not the domain's state, and a probe that misses a
selector seen before does not mean it is gone (a trimmed list, a guard that fired, a flaky
server). A line may carry the selectors earlier probes saw: `acme.com k2,selector1`. Those are
`carried`: always asked, first, even when guard 1 fires — and a carried selector that answers
under an NXDOMAIN `_domainkey` disproves the guard, so the full list is asked after all. A
carried selector asked and silent is listed in `stale`, never dropped: the consumer keeps its
last-seen time from the earlier row. Bare-domain lines work as before (nothing carried).

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
    ("pruned", pa.bool_()),             # _domainkey was NXDOMAIN, so the common list was not asked
                                        # (carried selectors still were; see selectors_probed)
    ("wildcard", pa.bool_()),           # the impossible selector answered; hits would be meaningless
    ("selectors_asked", pa.int16()),
    ("selectors_failed", pa.int16()),   # selectors whose lookup ended TIMEOUT / SERVFAIL / ERROR
    ("hits", pa.list_(HIT)),
    ("resolved_at", pa.timestamp("s", tz="UTC")),
    ("queries", pa.int16()),
    ("worker", pa.string()),
    ("source_file", pa.string()),
    # Added 2026-10-20; older rows read them as null. None of these says "no DKIM".
    ("dkim_visibility", pa.string()),   # visible | not_visible | not_visible_pruned | unknown_wildcard | unknown_failed
    ("selectors_probed", pa.list_(pa.string())),  # the names asked this probe, in order
    ("carried", pa.list_(pa.string())),  # previously seen selectors the input line supplied
    ("stale", pa.list_(pa.string())),    # carried, asked, and silent this probe: NOT gone
])

MAX_CARRIED = 16                    # a carried list is a handful of names; more is a bad input line
_SELECTOR_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_.")


def is_dkim_file(filename: str) -> bool:
    return filename.startswith((FILE_PREFIX, FULL_PREFIX))


def prunes(filename: str) -> bool:
    return not filename.startswith(FULL_PREFIX)


def read_domains(path) -> tuple[list[str], dict[str, tuple[str, ...]]]:
    """Domains in file order, and the previously seen selectors any line carried.

    A line is `domain` or `domain sel1,sel2` (commas and/or whitespace). Blanks, comments and
    duplicate domains are dropped as in cname_resolver.read_hosts; a duplicate's selectors are
    merged. A selector that is not a plain DNS label sequence, or the wildcard probe, is ignored.
    """
    domains, carried = [], {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().lower().replace(",", " ").split()
            if not parts or parts[0].startswith("#"):
                continue
            d = parts[0].rstrip(".")
            if not d:
                continue
            if d not in carried:
                domains.append(d)
                carried[d] = ()
            sels = [s.strip(".") for s in parts[1:]]
            sels = [s for s in sels if s and set(s) <= _SELECTOR_CHARS and s != WILDCARD_PROBE]
            carried[d] = tuple(dict.fromkeys(carried[d] + tuple(sels)))[:MAX_CARRIED]
    return domains, {d: s for d, s in carried.items() if s}


def visibility(row: dict) -> str:
    """The row's `dkim_visibility`. See the module docstring: there is no absence value."""
    if row["wildcard"]:
        return "unknown_wildcard"
    if row["hits"]:
        return "visible"
    if row["selectors_failed"]:
        return "unknown_failed"
    if row["pruned"]:
        return "not_visible_pruned"
    return "not_visible"


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
    """A CNAME chain is a hit whatever the final rcode; a key with no chain needs NOERROR.

    A delegation whose target has no key yet ends in NXDOMAIN, but the chain is still in the
    answer section and the selector is still set up: Microsoft 365's standby selector2 CNAMEs to
    selector2-<d>._domainkey.<tenant>.onmicrosoft.com, which does not exist until the key rotates.
    Such a hit has has_key=False, which is how the consumer tells it from a delegation with a key.
    A transient failure is never a hit, chain or not.
    """
    if res["rcode"] in TRANSIENT:
        return False
    return bool(res["cnames"]) or (res["rcode"] == "NOERROR" and res["has_key"])


async def resolve_domains(domains: list[str], *, qps: float, prune: bool = True,
                          nameserver: str = "127.0.0.1", timeout: float = 4.0, retries: int = 1,
                          parallel: int = 64, selectors: tuple = SELECTORS, lookup=lookup,
                          carried: dict[str, tuple[str, ...]] | None = None) -> list[dict]:
    """Probe every domain at `qps` (one limiter across all queries). `lookup` is injectable.

    `carried` maps a domain to the selectors earlier probes saw (read_domains); they are asked
    first and are never pruned away."""
    carried = carried or {}
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
        prior = tuple(carried.get(domain, ()))
        row = {"domain": domain, "domainkey_rcode": "NOT_ASKED", "pruned": False, "wildcard": False,
               "selectors_asked": 0, "selectors_failed": 0, "hits": [], "queries": 0,
               "selectors_probed": [], "carried": list(prior), "stale": []}

        async def probe_all(names) -> None:
            for sel in names:
                res, n = await ask(f"{sel}._domainkey.{domain}")
                row["queries"] += n
                row["selectors_asked"] += 1
                row["selectors_probed"].append(sel)
                if res["rcode"] in TRANSIENT:
                    row["selectors_failed"] += 1
                elif _answered(res):
                    row["hits"].append({"selector": sel, "cnames": res["cnames"],
                                        "has_key": res["has_key"]})
                elif sel in prior:
                    row["stale"].append(sel)

        async with sem:
            if prune:
                base, n = await ask(f"_domainkey.{domain}")
                row["queries"] += n
                row["domainkey_rcode"] = base["rcode"]
                if base["rcode"] == "NXDOMAIN":
                    row["pruned"] = True
            # A pruned domain with nothing carried is done. One with carried selectors still
            # asks them: the guard is wrong on some servers, and a seen selector outranks it.
            if not row["pruned"] or prior:
                probe, n = await ask(f"{WILDCARD_PROBE}._domainkey.{domain}")
                row["queries"] += n
                if _answered(probe):
                    row["wildcard"] = True
                    row["pruned"] = False       # something answered under _domainkey after all
                else:
                    await probe_all(prior)
                    if row["pruned"] and row["hits"]:
                        row["pruned"] = False   # guard disproven: ask the common list too
                    if not row["pruned"]:
                        await probe_all(s for s in selectors if s not in prior)
        row["dkim_visibility"] = visibility(row)
        row["resolved_at"] = datetime.now(timezone.utc).replace(microsecond=0)
        return row

    return await asyncio.gather(*(one(d) for d in domains))


def to_table(rows: list[dict], source_file: str, worker: str | None = None) -> pa.Table:
    worker = worker or socket.gethostname()
    names = [f.name for f in SCHEMA if f.name not in ("worker", "source_file")]
    return pa.Table.from_pylist(
        [{**{k: r[k] for k in names}, "worker": worker, "source_file": source_file} for r in rows],
        schema=SCHEMA)
