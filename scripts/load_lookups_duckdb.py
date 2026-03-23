#!/usr/bin/env python3
"""
Load brand lookups CSVs into DuckDB.

Environment:
  LOOKUPS_DB_PATH: Either a directory (e.g., /mnt/shared/lookups/) or a file path ending in .duckdb

Usage:
  export LOOKUPS_DB_PATH=/mnt/shared/lookups/
  python3 scripts/load_lookups_duckdb.py
"""
from __future__ import annotations
import os
from pathlib import Path

def _resolve_db_path(env_val: str | None) -> Path:
    if not env_val:
        return Path("lookups.duckdb").absolute()
    p = Path(env_val)
    if p.suffix == ".duckdb":
        return p
    return (p / "lookups.duckdb").absolute()

def main():
    import duckdb

    base = Path(__file__).resolve().parent.parent
    scaffold = base / "lookups_scaffold"
    db_path = _resolve_db_path(os.getenv("LOOKUPS_DB_PATH"))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Loading brand lookups into: {db_path}")

    with duckdb.connect(str(db_path)) as con:
        con.execute("PRAGMA disable_object_cache;")
        # Create tables if not exist
        con.execute("""
        CREATE TABLE IF NOT EXISTS brand_ns_catalog (brand TEXT, ns_root TEXT);
        CREATE TABLE IF NOT EXISTS brand_mx_catalog (brand TEXT, mx_root TEXT);
        CREATE TABLE IF NOT EXISTS brand_cname_catalog (brand TEXT, cname_root TEXT);
        CREATE TABLE IF NOT EXISTS brand_ip_ranges_catalog (brand TEXT, cidr TEXT);
        """)

        # Load CSVs if present
        def load_csv(table: str, fname: str):
            path = scaffold / fname
            if not path.exists():
                print(f"- Skipping {table}: {path} not found")
                return
            print(f"- Loading {table} from {path}")
            con.execute(f"DELETE FROM {table}")
            con.execute(
                f"COPY {table} FROM ? (AUTO_DETECT TRUE, HEADER TRUE)",
                [str(path)]
            )
            cnt = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  -> {table} rows: {cnt}")

        load_csv("brand_ns_catalog", "brand_ns_catalog.csv")
        load_csv("brand_mx_catalog", "brand_mx_catalog.csv")
        load_csv("brand_cname_catalog", "brand_cname_catalog.csv")
        load_csv("brand_ip_ranges_catalog", "brand_ip_ranges_catalog.csv")

    print("Done.")

if __name__ == "__main__":
    main()
