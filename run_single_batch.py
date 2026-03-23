#!/usr/bin/env python3
from __future__ import annotations
import asyncio
import sys
import argparse
import json
import random
import tempfile
import tldextract
from pathlib import Path
import pyarrow.parquet as pq
import pyarrow as pa
import csv

# Adjust import if your package root differs
from dns_module.dns_application import DNSApplication

NFS_BASE = Path("/mnt/shared/")
INPROGRESS = NFS_BASE / "inprogress"
# TLD groups for diagnostics
TLD_GROUPS = {
    "com_net": {"com", "net"},
    "uk_de": {"uk", "de"},
}

def tld_group(domain: str) -> str:
    try:
        suf = tldextract.extract(domain or "").suffix.lower()
        if suf in TLD_GROUPS["com_net"]:
            return "com_net"
        if suf in TLD_GROUPS["uk_de"]:
            return "uk_de"
        return "rest"
    except Exception:
        return "rest"
    
def convert_to_parquet(input_path: Path) -> Path:
    """
    Convert a TXT or CSV file to a temporary Parquet file with required schema.
    Returns path to temporary file.
    """
    domains = []
    
    print(f"Converting {input_path} to compatible Parquet format...")
    
    with open(input_path, 'r', encoding='utf-8') as f:
        # Check if CSV
        sample = f.read(1024)
        f.seek(0)
        has_header = False
        try:
            has_header = csv.Sniffer().has_header(sample)
        except Exception:
            pass

        if input_path.suffix.lower() == '.csv':
            reader = csv.DictReader(f) if has_header else csv.reader(f)
            if has_header:
                for row in reader:
                    # Try to find a domain column
                    d = row.get('domain') or row.get('url') or list(row.values())[0]
                    if d: domains.append(d)
            else:
                for row in reader:
                    if row: domains.append(row[0])
        else:
            # Assume text file, one domain per line
            for line in f:
                d = line.strip()
                if d: domains.append(d)

    if not domains:
        raise ValueError("No domains found in input file")

    print(f"Found {len(domains)} domains.")

    # Create PyArrow table with required schema
    # columns=["domain", "ns", "ip", "country_dm"]
    
    data = {
        "domain": domains,
        "ns": [""] * len(domains),
        "ip": [""] * len(domains),
        "country_dm": [""] * len(domains)
    }
    
    schema = pa.schema([
        ("domain", pa.string()),
        ("ns", pa.string()),
        ("ip", pa.string()),
        ("country_dm", pa.string())
    ])
    
    table = pa.Table.from_pydict(data, schema=schema)
    
    # Write to temp file
    fd, tmp_path = tempfile.mkstemp(suffix=".parquet")
    import os
    os.close(fd)
    
    pq.write_table(table, tmp_path)
    return Path(tmp_path)

def main():
    parser = argparse.ArgumentParser(description="Run DNS batch processing on a file.")
    parser.add_argument("input_file", nargs="?", help="Path to input file (parquet, txt, or csv)")
    parser.add_argument("--profile", default="default", help="Scoring profile to use")
    parser.add_argument("--nameservers", default="127.0.0.1",
                        help="Comma-separated list of DNS resolvers (default: 127.0.0.1; use 'system' for /etc/resolv.conf)")
    
    args = parser.parse_args()

    # Determine input file
    if args.input_file:
        input_path = Path(args.input_file)
        if not input_path.exists():
            print(f"Error: File {input_path} not found.")
            sys.exit(1)
            
        # Handle non-parquet input
        if input_path.suffix.lower() != '.parquet':
            try:
                real_input_path = convert_to_parquet(input_path)
                is_temp = True
            except Exception as e:
                print(f"Error converting input file: {e}")
                sys.exit(1)
        else:
            real_input_path = input_path
            is_temp = False
            
    else:
        # Legacy behavior: pick random file from NFS
        files = sorted(INPROGRESS.glob("*.parquet"))
        if not files:
            print(f"No parquet files in {INPROGRESS}")
            return
        real_input_path = random.choice(files)
        is_temp = False

    print(f"Processing: {real_input_path} (Original: {args.input_file or 'Random'})")
    
    # Configure directories
    # If explicit file provided, check if it's absolute or relative to cwd
    if args.input_file:
         # Use CWD for output if running local file
        work_dir = Path.cwd()
        input_dir = real_input_path.parent
        file_key = real_input_path.name
        output_dir = work_dir / "output"
        output_dir.mkdir(exist_ok=True)
    else:
        # Default NFS paths
        work_dir = Path("/mnt/shared")
        input_dir = real_input_path.parent
        file_key = real_input_path.name
        output_dir = work_dir # fallback
    
    try:
        ns_input = args.nameservers.strip().lower()
        if ns_input == 'system':
            # Pass None to let dnspython use /etc/resolv.conf
            ns_list = None
            print("Using system default resolver (/etc/resolv.conf)")
        else:
            ns_list = [x.strip() for x in args.nameservers.split(",") if x.strip()]
            print(f"Using manual nameservers: {ns_list}")

        app = DNSApplication(
            directory=str(work_dir),
            input_directory=str(input_dir),
            output_directory=str(output_dir),
            file_key=file_key,
            scoring_profile=[args.profile],
            nameservers=ns_list
        )

        asyncio.run(app.run_dns())
        print("✓ Batch complete.")

        # Summarize SERVFAIL/TIMEOUT domains by TLD group using the expanded output
        try:
            expanded_path = output_dir / f"{file_key}_expanded.parquet"
            if expanded_path.exists():
                tbl = pq.read_table(expanded_path)
                if "domain" in tbl.column_names and "errors_json" in tbl.column_names:
                    domains = [tbl.column("domain")[i].as_py() for i in range(tbl.num_rows)]
                    errs = [tbl.column("errors_json")[i].as_py() for i in range(tbl.num_rows)]

                    group_totals = {}
                    group_servfails = {}
                    group_timeouts = {}

                    for d, ej in zip(domains, errs):
                        g = tld_group(d)
                        group_totals[g] = group_totals.get(g, 0) + 1
                        has_sf = False
                        has_to = False
                        try:
                            m = json.loads(ej) if ej else {}
                            # Flag domain if any core lookup failed with SERVFAIL/TIMEOUT
                            for key in ("NS", "SOA", "A"):
                                v = m.get(key)
                                if v == "SERVFAIL":
                                    has_sf = True
                                if v == "TIMEOUT":
                                    has_to = True
                        except Exception:
                            pass

                        if has_sf:
                            group_servfails[g] = group_servfails.get(g, 0) + 1
                        if has_to:
                            group_timeouts[g] = group_timeouts.get(g, 0) + 1

                    print("\n== Core error domains by TLD group ==")
                    print("Group   total   SERVFAIL (pct)   TIMEOUT (pct)")
                    for g in ("com_net", "uk_de", "rest"):
                        total = group_totals.get(g, 0)
                        sf = group_servfails.get(g, 0)
                        to = group_timeouts.get(g, 0)
                        sf_pct = (sf / total * 100.0) if total else 0.0
                        to_pct = (to / total * 100.0) if total else 0.0
                        print(f"{g:<7} {total:<7} {sf:<7} ({sf_pct:5.1f}%)   {to:<7} ({to_pct:5.1f}%)")
                else:
                    print("\nExpanded output missing required columns for error summary.")
            else:
                print(f"\nExpanded output not found: {expanded_path}")
        except Exception as e:
            print(f"\nError summary skipped (error): {e}")
    except Exception as e:
        print(f"Execution failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup temp file if we created one
        if args.input_file and is_temp and real_input_path.exists():
            try:
                import os
                os.unlink(real_input_path)
                print("(Cleaned up temporary conversion file)")
            except Exception:
                pass

if __name__ == "__main__":
    main()
