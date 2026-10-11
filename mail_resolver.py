"""MX + SPF resolution of certstream-observed subdomains, on the cname_queue path.

WHY THIS EXISTS. The lake resolves mail records for the apex only, so the sending infrastructure a
domain runs on SUBDOMAINS (em.acme.com -> SendGrid, bounce.acme.com -> an ESP's MX, mg.acme.com ->
Mailgun) is invisible to it. cname_resolver already reaches those hosts, but asks one A query and
nothing else. This asks the same hosts for MX and TXT as well and keeps what was observed.

It rides the cname_queue path unchanged: same drop folder, same dedicated workers, same state
folders, never retries/. A host file whose name starts with FILE_PREFIX is resolved here instead
of by cname_resolver, and its rows go to their own Flight dataset, `mail_resolution`, which the
master lands at r2://domains-monitor/mail_resolution/ — outside DuckLake and the compactor, like
cname_resolution. ⚠ The master's sink branch must be deployed BEFORE any worker sends this
dataset: do_put stages a dataset it does not recognise, and the compactor uploads it to bronze.

WHAT A ROW IS, AND IS NOT. One row per host that was ASKED: an observation at resolved_at. The
host list is certstream / passive-DNS observed names, so the set is a floor on what exists, never
a census. This module records and does not interpret — which carrier an MX or an include belongs
to, and how much to trust it, is decided by the consumer. For that consumer:
  * `cnames` and `mx` are live routing decisions observed at resolution time;
  * `spf_includes` is authorisation text. It is an upper bound on what is in use: an include
    outlives the vendor it was added for.

QUERY BUDGET. Up to three queries per host (A, MX, TXT), all through one rate limiter, so a file
takes about three times as long as a cname file of the same size. MX and TXT are NOT asked when
the A query says the name does not exist or could not be reached (`NOT_ASKED`).

As in cname_resolver, every asyncio primitive is created inside the coroutine.
"""
from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone

import pyarrow as pa

from cname_resolver import RateLimiter, TRANSIENT, parse_response

DATASET = "mail_resolution"
FILE_PREFIX = "mail_"
SCHEMA = pa.schema([
    ("host", pa.string()),
    ("rcode", pa.string()),                 # of the A query, as in cname_resolution
    ("cnames", pa.list_(pa.string())),
    ("a", pa.list_(pa.string())),
    ("mx_status", pa.string()),             # PRESENT | NO_MX | NULL_MX | NXDOMAIN | SERVFAIL | TIMEOUT | ERROR | NOT_ASKED
    ("mx", pa.list_(pa.string())),          # "<preference>:<exchange>"
    ("txt_status", pa.string()),            # PRESENT | NO_TXT | NXDOMAIN | SERVFAIL | TIMEOUT | ERROR | NOT_ASKED
    ("spf", pa.list_(pa.string())),         # every v=spf1 record, verbatim; two or more is a permerror
    ("spf_includes", pa.list_(pa.string())),
    ("resolved_at", pa.timestamp("s", tz="UTC")),
    ("queries", pa.int16()),                # DNS queries sent for this host, retries included
    ("worker", pa.string()),
    ("source_file", pa.string()),
])
# The A-query outcomes after which MX / TXT are worth asking.
_ASK_MAIL_AFTER = ("NOERROR",)


def is_mail_file(filename: str) -> bool:
    return filename.startswith(FILE_PREFIX)


def parse_mx(response) -> dict:
    """MX status and records. MX rrsets are taken whatever their owner, so a host that is a CNAME
    reports the mail routing of the name it points at — which is the routing mail would follow."""
    import dns.rcode
    import dns.rdatatype

    rcode = dns.rcode.to_text(response.rcode())
    if rcode != "NOERROR":
        return {"mx_status": rcode, "mx": []}
    recs, saw_mx = [], False
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.MX:
            continue
        for rd in rrset:
            saw_mx = True
            exchange = rd.exchange.to_text().rstrip(".").lower()
            if exchange:                    # RFC 7505 null MX is "0 ." — an empty exchange
                recs.append((rd.preference, exchange))
    if recs:
        return {"mx_status": "PRESENT", "mx": [f"{p}:{h}" for p, h in sorted(recs)]}
    return {"mx_status": "NULL_MX" if saw_mx else "NO_MX", "mx": []}


def _is_spf(txt: str) -> bool:
    """RFC 7208 4.5: the record is exactly `v=spf1` or starts with `v=spf1 `."""
    t = txt.lower()
    return t == "v=spf1" or t.startswith("v=spf1 ")


def spf_includes(records: list[str]) -> list[str]:
    """The domains an SPF record delegates to: `include:` and `redirect=` targets. Macro targets
    (`%{...}`) are dropped: they are not a name."""
    out = set()
    for rec in records:
        for term in rec.split()[1:]:
            t = term.lower().lstrip("+-~?")
            for head in ("include:", "redirect="):
                if t.startswith(head):
                    target = t[len(head):].rstrip(".")
                    if target and "%" not in target:
                        out.add(target)
    return sorted(out)


def parse_txt(response) -> dict:
    import dns.rcode
    import dns.rdatatype

    rcode = dns.rcode.to_text(response.rcode())
    if rcode != "NOERROR":
        return {"txt_status": rcode, "spf": [], "spf_includes": []}
    spf, saw_txt = [], False
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.TXT:
            continue
        for rd in rrset:
            saw_txt = True
            txt = b"".join(rd.strings).decode("utf-8", "replace").strip()
            if _is_spf(txt):
                spf.append(txt)
    return {"txt_status": "PRESENT" if saw_txt else "NO_TXT", "spf": sorted(spf),
            "spf_includes": spf_includes(spf)}


_PARSERS = {"A": parse_response, "MX": parse_mx, "TXT": parse_txt}
_STATUS_KEY = {"A": "rcode", "MX": "mx_status", "TXT": "txt_status"}
_EMPTY = {
    "A": {"cnames": [], "a": [], "min_ttl": None},
    "MX": {"mx": []},
    "TXT": {"spf": [], "spf_includes": []},
}


async def lookup(host: str, rdtype: str, nameserver: str, timeout: float) -> dict:
    """One query, parsed. A transport failure becomes its own status, never an empty answer."""
    import dns.asyncquery
    import dns.exception
    import dns.flags
    import dns.message

    q = dns.message.make_query(host, rdtype)
    try:
        r = await dns.asyncquery.udp(q, nameserver, timeout=timeout)
        if r.flags & dns.flags.TC:
            r = await dns.asyncquery.tcp(q, nameserver, timeout=timeout)
    except dns.exception.Timeout:
        return {_STATUS_KEY[rdtype]: "TIMEOUT", **_EMPTY[rdtype]}
    except Exception:  # network errors, malformed responses
        return {_STATUS_KEY[rdtype]: "ERROR", **_EMPTY[rdtype]}
    return _PARSERS[rdtype](r)


async def resolve_hosts(hosts: list[str], *, qps: float, nameserver: str = "127.0.0.1",
                        timeout: float = 4.0, retries: int = 2, parallel: int = 64,
                        lookup=lookup) -> list[dict]:
    """A, then MX and TXT, for every host at `qps` (one limiter across all three). Transient
    failures are retried and then kept as their own status. `lookup` is injectable for tests."""
    limiter = RateLimiter(qps)
    sem = asyncio.Semaphore(parallel)

    async def ask(host: str, rdtype: str) -> tuple[dict, int]:
        res, sent = None, 0
        for attempt in range(retries + 1):
            sent += 1
            await limiter.wait()
            res = await lookup(host, rdtype, nameserver, timeout)
            if res[_STATUS_KEY[rdtype]] not in TRANSIENT:
                break
            await asyncio.sleep(1.0 * (attempt + 1))
        return res, sent

    async def one(host: str) -> dict:
        async with sem:
            a, queries = await ask(host, "A")
            if a["rcode"] in _ASK_MAIL_AFTER:
                mx, n1 = await ask(host, "MX")
                txt, n2 = await ask(host, "TXT")
                queries += n1 + n2
            else:
                mx = {"mx_status": "NOT_ASKED", **_EMPTY["MX"]}
                txt = {"txt_status": "NOT_ASKED", **_EMPTY["TXT"]}
        return {"host": host, "rcode": a["rcode"], "cnames": a["cnames"], "a": a["a"],
                **mx, **txt, "queries": queries,
                "resolved_at": datetime.now(timezone.utc).replace(microsecond=0)}

    return await asyncio.gather(*(one(h) for h in hosts))


def to_table(rows: list[dict], source_file: str, worker: str | None = None) -> pa.Table:
    worker = worker or socket.gethostname()
    names = [f.name for f in SCHEMA if f.name not in ("worker", "source_file")]
    return pa.Table.from_pylist(
        [{**{k: r[k] for k in names}, "worker": worker, "source_file": source_file} for r in rows],
        schema=SCHEMA)
