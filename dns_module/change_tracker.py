# dns_module/change_tracker.py
from __future__ import annotations

import json
import time
import os
import csv
from typing import Any, Dict, List, Optional, Tuple

import pyarrow as pa
import pyarrow.parquet as pq

from kv.lmdb_store import LMDBActivity

# ── Delta CSV columns ─────────────────────────────────────────────────────────
# v1 had: domain, is_active, last_seen_ts, dns_sig, mx_regdom, mx_ips
# v2 adds: ns, a, mx, cname, ptr, changed_records
# Master can call kv.upsert_from_delta(row) directly with no further lookups.
DELTA_FIELDS = [
    "domain",
    "is_active",
    "last_seen_ts",
    "dns_sig",
    "ns",               # JSON array  e.g. '["ns1.foo.com","ns2.foo.com"]'
    "a",                # JSON array  e.g. '["1.2.3.4"]'
    "mx",               # JSON array  e.g. '["mail.foo.com"]'
    "cname",            # JSON array
    "ptr",              # JSON array
    "mx_regdom",        # plain string
    "mx_ips",           # pipe-joined string (kept for compat)
    "changed_records",  # JSON array  e.g. '["ns","mx"]', [] = new domain
]


# ── Normalisation ─────────────────────────────────────────────────────────────

def _to_list(val: Any) -> List[str]:
    """Normalise any wire format → sorted deduplicated list of strings."""
    if val is None:
        return []
    if isinstance(val, list):
        items = [str(x).strip().rstrip(".").lower() for x in val if x]
    elif isinstance(val, str):
        items = []
        for part in val.replace("\n", " ").split("|"):
            for sub in part.split(","):
                for tok in sub.split():
                    s = tok.strip().rstrip(".").lower()
                    if s:
                        items.append(s)
    else:
        items = [str(val).strip().rstrip(".").lower()] if val else []
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return sorted(out)


def _jdump(lst: List[str]) -> str:
    return json.dumps(lst, separators=(",", ":"))


# ── Signature helper (kept for any callers that used the old module-level fn) ─

def dns_sig(ns: str, a: str, mx_regdom: str) -> bytes:
    """Thin wrapper — delegates to LMDBActivity for consistency."""
    return LMDBActivity.compute_signature_values(
        ns=ns, a=a, mx_regdom=mx_regdom,
        registered_domain="", mx_ips="",
    )


# ── Core per-row evaluator ────────────────────────────────────────────────────

def _row_needs_enrich(
    prev:      Optional[Dict],   # result of kv.batch_get_sig() for this domain
    domain:    str,
    ns:        List[str],
    a:         List[str],
    mx:        List[str],
    cname:     List[str],
    ptr:       List[str],
    status:    str,
    # kept for signature compat — still used to compute dns_sig for delta
    ns_str:    str = "",
    a_str:     str = "",
    mx_regdom: str = "",
    reg_domain: str = "",
    mx_ips:    str = "",
) -> Tuple[bool, bool, bytes, List[str]]:
    """
    Returns (needs_enrich, reactivated, new_sig_bytes, changed_record_types).

    needs_enrich          True if domain is new, reactivated, or any record changed
    reactivated           True if previously inactive and now active
    new_sig_bytes         sha1 bytes for the delta CSV
    changed_record_types  list of record type strings that actually differ
    """
    is_active = str(status or "").upper() != "NXDOMAIN"

    # Compute sig the same way as before so delta CSV is consistent
    new_sig = LMDBActivity.compute_signature_values(
        ns=ns_str or "|".join(ns),
        a=a_str or "|".join(a),
        mx_regdom=mx_regdom or (mx[0] if mx else ""),
        registered_domain=reg_domain or domain,
        mx_ips=mx_ips,
    )

    if prev is None:
        # New domain — always enrich, no prior values to diff
        return True, False, new_sig, []

    was_active  = bool(prev.get("is_active", True))
    reactivated = (not was_active) and is_active

    # Compare actual record values, not hashes
    changed: List[str] = []
    for rtype, new_val in (("ns", ns), ("a", a), ("mx", mx),
                            ("cname", cname), ("ptr", ptr)):
        old_val = sorted(prev.get(rtype) or [])
        if new_val != old_val:
            changed.append(rtype)

    # For v1 records we don't have old values — fall back to sig comparison
    if prev.get("_v1"):
        stored_sig = prev.get("sig", "")
        new_sig_str = new_sig.decode("ascii", "ignore")
        if stored_sig != new_sig_str:
            # Something changed but we don't know what — mark all three key types
            changed = [r for r in ("ns", "a", "mx") if r not in changed] + changed

    needs = bool(reactivated or changed)
    return needs, reactivated, new_sig, changed


# ── Vectorised annotator ──────────────────────────────────────────────────────

def annotate_change_flags_arrow(
    table: List[Dict] | pa.Table,
    kv:    LMDBActivity,
    *,
    domain_col:            str = "domain",
    ns_col:                str = "ns_raw",       # pipe-joined string (for sig compat)
    a_col:                 str = "a",
    mx_regdom_col:         str = "mx_regdom_final",
    status_col:            str = "status",
    registered_domain_col: str = "registered_domain",
    mx_ips_col:            str = "mx_ips",
    # List-form columns — preferred for actual value comparison
    ns_list_col:           str = "ns_list_norm",
    a_list_col:            str = "a_list",
    mx_list_col:           str = "mx_list",
    cname_list_col:        str = "cname_list",
    ptr_list_col:          str = "ptr_list",
) -> Tuple[pa.Table, List[Dict]]:
    """
    Annotates a batch of resolved DNS rows with change flags.

    Adds two bool columns to the returned Arrow table:
      needs_enrich   True if domain is new or any record changed
      reactivated    True if domain was inactive and is now active

    Returns a list of delta dicts — one per changed/new domain.
    Each delta carries actual record lists so the master can call
    kv.upsert_from_delta(delta) with no further LMDB reads.
    """
    # ── Normalise input ───────────────────────────────────────────
    if isinstance(table, pa.Table):
        rows = table.to_pylist()
    elif isinstance(table, list):
        if not table:
            empty = pa.table({
                domain_col:     pa.array([], type=pa.string()),
                "needs_enrich": pa.array([], type=pa.bool_()),
                "reactivated":  pa.array([], type=pa.bool_()),
            })
            return empty, []
        rows = table
    else:
        raise TypeError(f"annotate_change_flags_arrow: expected list or pa.Table, got {type(table)}")

    # ── Single bulk LMDB read for the whole batch ─────────────────
    domains = [(r.get(domain_col) or "").lower() for r in rows]
    prev_map = kv.batch_get_sig(domains)

    # ── Evaluate each row ─────────────────────────────────────────
    needs_list: List[bool] = []
    react_list: List[bool] = []
    deltas:     List[Dict] = []
    now_ts = int(time.time())

    for domain, row in zip(domains, rows):
        status    = str(row.get(status_col) or "")
        ns_str    = str(row.get(ns_col)         or "")
        a_str     = str(row.get(a_col)          or "")
        mx_regdom = str(row.get(mx_regdom_col)  or "").lower()
        reg_domain = str(row.get(registered_domain_col) or "").lower() or domain
        mx_ips    = str(row.get(mx_ips_col)     or "")

        # Prefer pre-split list columns; fall back to parsing pipe-joined strings
        ns    = row.get(ns_list_col)    or _to_list(ns_str)
        a     = row.get(a_list_col)     or _to_list(a_str)
        mx    = row.get(mx_list_col)    or _to_list(mx_regdom)
        cname = row.get(cname_list_col) or []
        ptr   = row.get(ptr_list_col)   or []

        # Ensure sorted lists
        ns = sorted(_to_list(ns) if not isinstance(ns, list) else ns)
        a  = sorted(_to_list(a)  if not isinstance(a,  list) else a)
        mx = sorted(_to_list(mx) if not isinstance(mx, list) else mx)

        prev = prev_map.get(domain)

        needs, reactivated, new_sig, changed = _row_needs_enrich(
            prev=prev, domain=domain,
            ns=ns, a=a, mx=mx, cname=cname, ptr=ptr,
            status=status,
            ns_str=ns_str, a_str=a_str, mx_regdom=mx_regdom,
            reg_domain=reg_domain, mx_ips=mx_ips,
        )

        needs_list.append(needs)
        react_list.append(reactivated)

        if needs:
            is_active = str(status).upper() != "NXDOMAIN"
            deltas.append({
                "domain":           domain,
                "is_active":        "true" if is_active else "false",
                "last_seen_ts":     str(now_ts),
                "dns_sig":          new_sig.decode("ascii", "ignore"),
                "ns":               _jdump(ns),
                "a":                _jdump(a),
                "mx":               _jdump(mx),
                "cname":            _jdump(cname),
                "ptr":              _jdump(ptr),
                "mx_regdom":        mx_regdom,
                "mx_ips":           mx_ips,
                "changed_records":  _jdump(changed),  # [] = brand new domain
            })

    # ── Build annotated Arrow table ───────────────────────────────
    try:
        base_table = pa.Table.from_pylist(rows)
    except Exception:
        base_table = pa.table({domain_col: pa.array(domains, type=pa.string())})

    col_names = set(base_table.column_names)
    needs_arr = pa.array(needs_list, type=pa.bool_())
    react_arr = pa.array(react_list, type=pa.bool_())

    if "needs_enrich" in col_names:
        base_table = base_table.set_column(
            base_table.schema.get_field_index("needs_enrich"), "needs_enrich", needs_arr)
    else:
        base_table = base_table.append_column("needs_enrich", needs_arr)

    if "reactivated" in col_names:
        base_table = base_table.set_column(
            base_table.schema.get_field_index("reactivated"), "reactivated", react_arr)
    else:
        base_table = base_table.append_column("reactivated", react_arr)

    return base_table, deltas


# ── Delta writer ──────────────────────────────────────────────────────────────

def write_activity_delta_parquet(deltas: List[Dict], out_path: str) -> None:
    if not deltas:
        return
    
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    
    # Deserialise JSON strings back to native lists
    rows = []
    for d in deltas:
        rows.append({
            "domain":          d["domain"],
            "is_active":       d["is_active"] == "true",
            "last_seen_ts":    int(d["last_seen_ts"]),
            "dns_sig":         d["dns_sig"],
            "ns":              json.loads(d["ns"]),
            "a":               json.loads(d["a"]),
            "mx":              json.loads(d["mx"]),
            "cname":           json.loads(d["cname"]),
            "ptr":             json.loads(d["ptr"]),
            "mx_regdom":       d["mx_regdom"],
            "mx_ips":          d["mx_ips"],
            "changed_records": json.loads(d["changed_records"]),
        })
    
    table = pa.Table.from_pylist(rows)
    pq.write_table(table, out_path, compression="snappy")