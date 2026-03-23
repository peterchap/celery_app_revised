#!/usr/bin/env python3
"""
Standalone runner for dns_module.dns_fetcher.DNSFetcher that uses the system resolver
(configuration such as your local Unbound on 127.0.0.1).

Usage:
  python run_dns_fetcher.py example.com --log /tmp/dnsfetch.log --timeout 3 --retries 2

Notes:
- This script does NOT create an explicit aiodns.DNSResolver with nameservers=[...],
  so aiodns will use the system resolver configuration (e.g. /etc/resolv.conf). That
  lets it pick up your Unbound configuration as requested.
- Logs (diagnostics + final JSON output) are written to the logfile you specify.
"""
from __future__ import annotations
import argparse
import asyncio
import json
import logging
import sys
from typing import Any

from dns_module.dns_fetcher import DNSFetcher


def to_jsonable(obj: Any) -> Any:
    """
    Try to convert DNSRecords or arbitrary objects into something JSON-serializable.
    Falls back to str() for unknown types.
    """
    # handle simple mapping-like objects / dataclasses
    try:
        # dataclass-like or object with __dict__
        if hasattr(obj, "__dict__"):
            d = {}
            for k, v in vars(obj).items():
                d[k] = to_jsonable(v)
            return d
        # mapping types
        if isinstance(obj, dict):
            return {k: to_jsonable(v) for k, v in obj.items()}
        # iterables
        if isinstance(obj, (list, tuple, set)):
            return [to_jsonable(v) for v in obj]
        # primitives
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        # fallback to str
        return str(obj)
    except Exception:
        return str(obj)


async def run_domain(domain: str, timeout: float, retries: int, logfile: str, verbose: bool):
    # Configure a simple file logger
    logger = logging.getLogger("dns_fetcher")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Avoid adding multiple handlers if this function is called more than once
    if not logger.handlers:
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG if verbose else logging.INFO)
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    # DNSFetcher expects a callable like logger.info
    logfunc = logger.info

    logger.info(f"Starting DNSFetcher for domain={domain} timeout={timeout} retries={retries}")
    # Do NOT pass an explicit aiodns resolver here so the system resolver (Unbound) is used.
    fetcher = DNSFetcher(domain, logger=logfunc, dns_timeout_s=timeout, retries=retries)

    try:
        rec = await fetcher.fetch_records()
    except Exception as e:
        logger.exception("fetch_records() raised an exception")
        print(f"Error: fetch_records raised an exception. See logfile: {logfile}", file=sys.stderr)
        return 2

    if rec is None:
        logger.info("fetch_records returned None (no DNSRecords).")
        print(f"No DNSRecords returned. See logfile: {logfile}")
        return 0

    # Convert to JSON-able structure and log it
    try:
        payload = to_jsonable(rec)
        pretty = json.dumps(payload, indent=2, default=str)
        logger.info("=== DNSFetcher result JSON ===\n" + pretty)
        # Also write a compact JSON to a separate file next to the log (optional)
        try:
            outpath = logfile + ".result.json"
            with open(outpath, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
            logger.info(f"Wrote compact JSON result to {outpath}")
            print(f"Done. Logs: {logfile}  Result JSON: {outpath}")
        except Exception:
            logger.exception("Failed to write result JSON file; results remain in the log")
            print(f"Done. Logs: {logfile} (result JSON could not be written)", file=sys.stderr)
    except Exception:
        logger.exception("Failed to serialize DNSRecords; falling back to str()")
        logger.info("DNSRecords (str): " + str(rec))
        print(f"Done. Logs: {logfile}")

    return 0


def main():
    p = argparse.ArgumentParser(description="Run DNSFetcher for one domain (use system resolver / Unbound).")
    p.add_argument("domain", help="Domain to fetch (e.g. example.com)")
    p.add_argument("--timeout", type=float, default=3.0, help="DNS lookup timeout (seconds)")
    p.add_argument("--retries", type=int, default=2, help="Number of resolver tries")
    p.add_argument("--log", default="/tmp/dnsfetch.log", help="Path to logfile (default: /tmp/dnsfetch.log)")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = p.parse_args()

    # Run the async runner
    try:
        rc = asyncio.run(run_domain(args.domain, args.timeout, args.retries, args.log, args.verbose))
        sys.exit(rc or 0)
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()