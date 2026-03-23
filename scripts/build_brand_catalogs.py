#!/usr/bin/env python3
"""
Build brand catalogs (NS/MX/CNAME) by resolving top brands and writing CSVs.

Inputs:
  - CSV at lookups_scaffold/brands_input.csv with columns: brand, domain

Outputs:
  - lookups_scaffold/brand_ns_catalog.csv
  - lookups_scaffold/brand_mx_catalog.csv
  - lookups_scaffold/brand_cname_catalog.csv

Notes:
  - ns_root values are exact NS hostnames (normalized, no trailing dot).
  - mx_root and cname_root are reduced to last two labels.
  - Nameservers default to DNS_NAMESERVERS env or 127.0.0.53.
"""
from __future__ import annotations
import asyncio
import csv
import os
from pathlib import Path
from typing import List, Set, Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver

BASE = Path(__file__).resolve().parent.parent
SCAFFOLD = BASE / "lookups_scaffold"

def normalize_host(s: str) -> str:
    return (s or "").strip().rstrip(".").lower()

def last_two_labels(host: str) -> str:
    h = normalize_host(host)
    parts = h.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h

async def resolve_records(resolver: dns.asyncresolver.Resolver, brand: str, domain: str) -> Tuple[Set[str], Set[str], Set[str]]:
    ns_roots: Set[str] = set()
    mx_roots: Set[str] = set()
    cname_roots: Set[str] = set()
    # NS
    try:
        ans = await resolver.resolve(domain, "NS")
        for rr in ans:
            ns_roots.add(normalize_host(str(rr.target)))
    except Exception:
        pass
    # MX
    try:
        ans = await resolver.resolve(domain, "MX")
        for rr in ans:
            mx_roots.add(last_two_labels(str(rr.exchange)))
    except Exception:
        pass
    # CNAME (www)
    try:
        ans = await resolver.resolve("www." + domain, "CNAME")
        for rr in ans:
            cname_roots.add(last_two_labels(str(rr.target)))
    except Exception:
        pass
    return ns_roots, mx_roots, cname_roots

async def main():
    # Nameservers
    ns_env = os.getenv("DNS_NAMESERVERS", "127.0.0.53")
    nameservers = [x.strip() for x in ns_env.split(",") if x.strip()]
    timeout = float(os.getenv("DNS_TIMEOUT", "3"))
    lifetime = float(os.getenv("DNS_LIFETIME", "5"))
    concurrency = int(os.getenv("BRAND_BUILD_CONCURRENCY", "8"))

    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = lifetime

    input_csv = SCAFFOLD / "brands_input.csv"
    if not input_csv.exists():
        raise SystemExit(f"Input not found: {input_csv}")

    brands: List[Tuple[str, str]] = []
    with open(input_csv, newline="", encoding="utf-8") as f:
        rd = csv.DictReader((row for row in f if not row.startswith('#')))
        for row in rd:
            brand = (row.get("brand") or "").strip()
            domain = (row.get("domain") or "").strip()
            if brand and domain:
                brands.append((brand.lower(), normalize_host(domain)))

    sem = asyncio.Semaphore(concurrency)
    ns_rows: Set[Tuple[str, str]] = set()
    mx_rows: Set[Tuple[str, str]] = set()
    cn_rows: Set[Tuple[str, str]] = set()

    async def run_one(b: str, d: str):
        async with sem:
            ns_set, mx_set, cn_set = await resolve_records(resolver, b, d)
            for v in ns_set:
                ns_rows.add((b, v))
            for v in mx_set:
                mx_rows.add((b, v))
            for v in cn_set:
                cn_rows.add((b, v))

    await asyncio.gather(*[run_one(b, d) for b, d in brands])

    # Write outputs
    out_ns = SCAFFOLD / "brand_ns_catalog.csv"
    out_mx = SCAFFOLD / "brand_mx_catalog.csv"
    out_cn = SCAFFOLD / "brand_cname_catalog.csv"

    def write_csv(path: Path, header: Tuple[str, str], rows: Set[Tuple[str, str]]):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            for a, b in sorted(rows):
                w.writerow([a, b])

    write_csv(out_ns, ("brand", "ns_root"), ns_rows)
    write_csv(out_mx, ("brand", "mx_root"), mx_rows)
    write_csv(out_cn, ("brand", "cname_root"), cn_rows)

    print(f"Wrote: {out_ns}")
    print(f"Wrote: {out_mx}")
    print(f"Wrote: {out_cn}")

if __name__ == "__main__":
    asyncio.run(main())
