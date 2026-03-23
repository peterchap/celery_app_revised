#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json
import argparse
import asyncio
from typing import Dict, List, Optional, Tuple

import ipaddress
import pyarrow as pa
import tldextract

# Workspace modules
from dns_module import dns_lookup
# Removed risk and annotation module imports
def _normalize_host(h: str) -> str:
    # Lowercase, strip trailing dot
    h = (h or "").strip().lower()
    return h[:-1] if h.endswith(".") else h


def _registered_domain(name: str) -> str:
    ext = tldextract.extract(name or "", include_psl_private_domains=True)
    reg = ext.top_domain_under_public_suffix or ""
    return reg.lower()


def _mx_target_from_answer(ans: str) -> str:
    # Try to pull the MX host from common formats:
    # - "10 mx.example.com."
    # - "mx.example.com."
    # - "mx.example.com"
    s = ans.strip()
    parts = s.split()
    # If first token is a preference number, last token should be host
    if len(parts) > 1 and parts[0].isdigit():
        host = parts[-1]
    else:
        host = parts[-1] if parts else ""
    return _normalize_host(host)


async def lookup_all(domain: str,
                     nameservers: Optional[List[str]],
                     sem_limit: int = 8) -> Dict[str, Tuple[str, List[str], int]]:
    # Resolver + semaphore
    if nameservers is None:
        ns_env = os.getenv("DNS_NAMESERVERS", "127.0.0.1")
        nameservers = [s.strip() for s in ns_env.split(",") if s.strip()]
    resolver = dns_lookup.get_default_resolver(nameservers=nameservers)
    dns_lookup.set_default_semaphore(limit=sem_limit)
    semaphore = dns_lookup.default_semaphore()

    async def do(rtype: str):
        rcode, answers, ttl = await dns_lookup.perform_lookup(
            rtype, domain, resolver=resolver, semaphore=semaphore, use_lmdb=False
        )
        return rcode, answers or [], ttl or 0

    # Core records
    tasks = {
        "NS": asyncio.create_task(do("NS")),
        "SOA": asyncio.create_task(do("SOA")),
        "A": asyncio.create_task(do("A")),
        "AAAA": asyncio.create_task(do("AAAA")),
        "MX": asyncio.create_task(do("MX")),
        "TXT": asyncio.create_task(do("TXT")),
        "CAA": asyncio.create_task(do("CAA")),
    }
    results: Dict[str, Tuple[str, List[str], int]] = {}
    for rt, t in tasks.items():
        results[rt] = await t
    return results


def to_arrow_base(domain: str, results: Dict[str, Tuple[str, List[str], int]]) -> pa.Table:
    # NS string normalized, joined
    ns_answers = results.get("NS", ("", [], 0))[1]
    ns_list = [_normalize_host(a) for a in ns_answers if a]
    ns_str = "|".join(sorted(set(ns_list)))

    # MX normalization
    mx_answers = results.get("MX", ("", [], 0))[1]
    mx_host = ""
    mx_regdom = ""
    if mx_answers:
        mx_host = _mx_target_from_answer(mx_answers[0])
        mx_regdom = _registered_domain(mx_host)

    # Registered domain for the input
    regdom = _registered_domain(domain)

    # ip_int from first A
    a_answers = results.get("A", ("", [], 0))[1]
    ip_int_val = None
    if a_answers:
        try:
            ip_int_val = int(ipaddress.ip_address(a_answers[0]))
        except Exception:
            ip_int_val = None

    data = {
        "domain": [domain],
        "registered_domain": [regdom],
        "ns": [ns_str],
        "mx_host_norm": [mx_host],
        "mx_regdom_norm": [mx_regdom],
        "ip_int": [ip_int_val if ip_int_val is not None else None],
    }
    schema = pa.schema([
        ("domain", pa.string()),
        ("registered_domain", pa.string()),
        ("ns", pa.string()),
        ("mx_host_norm", pa.string()),
        ("mx_regdom_norm", pa.string()),
        ("ip_int", pa.int64()),
    ])
    return pa.Table.from_pydict(data, schema=schema)


def print_dns_summary(domain: str, results: Dict[str, Tuple[str, List[str], int]]) -> None:
    print(f"\n== DNS Records for {domain} ==")
    for rt in ["NS","SOA","A","AAAA","MX","TXT","CAA"]:
        rcode, answers, ttl = results.get(rt, ("", [], 0))
        print(f"{rt:<5} rcode={rcode:<10} ttl={ttl:<6} answers={answers}")


# Print functions removed

async def main() -> None:
    parser = argparse.ArgumentParser(description="Run DNS, labels, and risk for a single domain.")
    parser.add_argument("domain", help="Domain to analyze, e.g. example.com")
    parser.add_argument("--nameservers", default=None, help="Comma-separated resolvers, default from DNS_NAMESERVERS")
    parser.add_argument("--sem", type=int, default=int(os.getenv("DNS_SEMAPHORE_LIMIT", "8")), help="Semaphore limit for lookups")
    parser.add_argument("--duckdb", default=os.getenv("LOOKUPS_DUCKDB", "/mnt/shared/lookups/lookups.duckdb"), help="DuckDB file for label enrichment")
    parser.add_argument("--profile", default="default", help="Risk scoring profile (see risk_module/score_config.yaml)")
    args = parser.parse_args()

    nameservers = [s.strip() for s in args.nameservers.split(",")] if args.nameservers else None

    # DNS
    results = await lookup_all(args.domain, nameservers=nameservers, sem_limit=args.sem)
    print_dns_summary(args.domain, results)

    # Base Arrow
    base = to_arrow_base(args.domain, results)

    # Label and Risk enrichment removed for strictly DNS focused processor


if __name__ == "__main__":
    asyncio.run(main())