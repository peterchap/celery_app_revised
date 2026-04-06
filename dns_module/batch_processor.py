# dns_module/batch_processor.py
from __future__ import annotations
import asyncio
import json
import time
import os
import re
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.flight as flight

from datetime import datetime
from typing import Iterable, List, Tuple, Dict, Any, Optional

from .entity_hasher import hash_domain, hash_ip
from .dns_records import DNSRecord
from .dns_fetcher import fetch_batch, DEFAULT_BATCH_WORKERS
from .dns_utils import ip_to_int
from kv.lmdb_store import LMDBActivity
from .change_tracker import annotate_change_flags_arrow, write_activity_delta_csv

from .logger import get_child_logger
log = get_child_logger("batch_processor")

DEFAULT_WORKERS = DEFAULT_BATCH_WORKERS
DEFAULT_SEMAPHORE_LIMIT = 800
NFS_BASE = Path(os.getenv("NFS_BASE", "/mnt/shared/"))


def _normalize_ns_value(ns_in: Any) -> str:
    tokens: List[str] = []
    try:
        if isinstance(ns_in, list):
            raw = [str(x) for x in ns_in if x]
        elif isinstance(ns_in, str):
            raw = []
            for part in ns_in.replace("\n", " ").split("|"):
                for sub in part.split(","):
                    for w in sub.split():
                        raw.append(w)
        else:
            raw = []
        seen = set()
        for r in raw:
            s = r.strip().rstrip('.').lower()
            if s and s not in seen:
                seen.add(s)
                tokens.append(s)
    except Exception:
        tokens = []
    return "|".join(tokens)


def _normalize_ns_list(ns_in: Any) -> List[str]:
    try:
        if isinstance(ns_in, list):
            raw = [str(x) for x in ns_in if x]
        elif isinstance(ns_in, str):
            raw = []
            for part in ns_in.replace("\n", " ").split("|"):
                for sub in part.split(","):
                    for w in sub.split():
                        raw.append(w)
        else:
            raw = []
        seen = set()
        out: List[str] = []
        for r in raw:
            s = r.strip().rstrip('.').lower()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out
    except Exception:
        return []


def _load_brand_ns_catalog(db_path: str | Path) -> Optional[pa.Table]:
    try:
        import duckdb
        with duckdb.connect(str(db_path), read_only=True) as con:
            return con.execute("SELECT * FROM brand_ns_catalog").arrow()
    except Exception:
        return None


def _load_brand_mx_catalog(db_path: str | Path) -> Optional[pa.Table]:
    try:
        import duckdb
        with duckdb.connect(str(db_path), read_only=True) as con:
            return con.execute("SELECT * FROM brand_mx_catalog").arrow()
    except Exception:
        return None


def _load_brand_cname_catalog(db_path: str | Path) -> Optional[pa.Table]:
    try:
        import duckdb
        with duckdb.connect(str(db_path), read_only=True) as con:
            return con.execute("SELECT * FROM brand_cname_catalog").arrow()
    except Exception:
        return None


def _load_brand_ip_ranges_catalog(db_path: str | Path) -> Optional[pa.Table]:
    try:
        import duckdb
        with duckdb.connect(str(db_path), read_only=True) as con:
            return con.execute("SELECT * FROM brand_ip_ranges_catalog").arrow()
    except Exception:
        return None


def _ensure_enricher_columns(table: pa.Table) -> pa.Table:
    try:
        cols = set(table.column_names)
        nrows = table.num_rows
        required = {
            "domain": pa.string(),
            "registered_domain": pa.string(),
            "mx_host_norm": pa.string(),
            "mx_regdom_norm": pa.string(),
            "ns": pa.string(),
            "ip_int": pa.int64(),
            "ns_ips": pa.string(),
            "ns_ip_int": pa.int64(),
        }
        for name, dtype in required.items():
            if name not in cols:
                if pa.types.is_string(dtype):
                    arr = pa.array([""] * nrows, type=pa.string())
                elif pa.types.is_int64(dtype):
                    arr = pa.nulls(nrows, type=pa.int64())
                else:
                    arr = pa.nulls(nrows, type=dtype)
                table = table.append_column(name, arr)
            else:
                try:
                    idx = table.schema.get_field_index(name)
                    col = table.column(name)
                    if str(col.type) == "null":
                        if name in ("ip_int", "ns_ip_int"):
                            new_arr = pa.nulls(nrows, type=pa.int64())
                        elif name in ("domain", "registered_domain", "mx_host_norm",
                                      "mx_regdom_norm", "ns", "ns_ips"):
                            new_arr = pa.array([""] * nrows, type=pa.string())
                        else:
                            new_arr = pa.nulls(nrows, type=dtype)
                        table = table.set_column(idx, name, new_arr)
                except Exception:
                    pass
        return table
    except Exception:
        return table


def _safe_serialize(obj):
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _safe_serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_safe_serialize(v) for v in obj]
    return str(obj)


def _dnsrecord_to_row(rec: DNSRecord) -> Dict[str, Any]:
    """Convert DNSRecord to compact row — used for retries only."""
    try:
        records_json = json.dumps(rec.records, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        try:
            records_json = json.dumps(_safe_serialize(rec.records), ensure_ascii=False, separators=(",", ":"))
        except Exception:
            records_json = "{}"
    try:
        errors_json = json.dumps(rec.errors, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        try:
            errors_json = json.dumps(_safe_serialize(rec.errors), ensure_ascii=False, separators=(",", ":"))
        except Exception:
            errors_json = "{}"
    try:
        meta_json = json.dumps(rec.meta, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        try:
            meta_json = json.dumps(_safe_serialize(rec.meta), ensure_ascii=False, separators=(",", ":"))
        except Exception:
            meta_json = "{}"
    return {
        "domain": str(rec.domain),
        "status": str(rec.status),
        "records_json": records_json,
        "errors_json": errors_json,
        "meta_json": meta_json,
    }


def get_dns_schema():
    """Compact schema — used for retries only."""
    return pa.schema([
        pa.field("domain", pa.string()),
        pa.field("status", pa.string()),
        pa.field("records_json", pa.string()),
        pa.field("errors_json", pa.string()),
        pa.field("meta_json", pa.string()),
    ])


def get_graph_domain_schema():
    return pa.schema([
        pa.field("domain_id", pa.uint64()),
        pa.field("domain", pa.string()),
        pa.field("apex", pa.string()),
        pa.field("tld", pa.string()),
        pa.field("first_seen_ts", pa.timestamp('us')),
        pa.field("last_seen_ts", pa.timestamp('us')),
        pa.field("source_flags", pa.string())
    ])


def get_graph_ip_schema():
    return pa.schema([
        pa.field("ip_id", pa.uint64()),
        pa.field("ip", pa.string()),
        pa.field("ip_version", pa.uint8()),
        pa.field("first_seen_ts", pa.timestamp('us')),
        pa.field("last_seen_ts", pa.timestamp('us'))
    ])


def get_graph_edge_schema():
    return pa.schema([
        pa.field("src_type", pa.string()),
        pa.field("src_id", pa.uint64()),
        pa.field("dst_type", pa.string()),
        pa.field("dst_id", pa.uint64()),
        pa.field("edge_type", pa.string()),
        pa.field("first_seen_ts", pa.timestamp('us')),
        pa.field("last_seen_ts", pa.timestamp('us')),
        pa.field("last_observed_ts", pa.timestamp('us')),
        pa.field("attrs", pa.string())
    ])


def _join_list(val: Any) -> str:
    try:
        if isinstance(val, list):
            return "|".join([str(x) for x in val if x is not None])
        if val is None:
            return ""
        return str(val)
    except Exception:
        return ""


def _dnsrecord_to_expanded_row(rec: DNSRecord) -> Dict[str, Any]:
    rd = getattr(rec, "records", {}) or {}
    meta = getattr(rec, "meta", {}) or {}
    errors = getattr(rec, "errors", {}) or {}

    def g(key: str) -> Any:
        return rd.get(key)

    try:
        meta_json = json.dumps(_safe_serialize(meta), ensure_ascii=False, separators=(",", ":"))
    except Exception:
        meta_json = "{}"
    try:
        errors_json = json.dumps(_safe_serialize(errors), ensure_ascii=False, separators=(",", ":"))
    except Exception:
        errors_json = "{}"
    try:
        records_json = json.dumps(_safe_serialize(rd), ensure_ascii=False, separators=(",", ":"))
    except Exception:
        records_json = "{}"

    def _split_tokens(v: Any) -> List[str]:
        try:
            if isinstance(v, list):
                out = [str(x).strip() for x in v if x is not None]
            elif isinstance(v, str):
                tmp: List[str] = []
                for part in v.replace("\n", " ").split("|"):
                    for sub in part.split(","):
                        for w in sub.split():
                            tmp.append(w)
                out = [w.strip() for w in tmp if w.strip()]
            else:
                out = []
            return [s.rstrip('.') for s in out]
        except Exception:
            return []

    def _parse_mx_list(v: Any) -> List[Dict[str, Any]]:
        items = _split_tokens(v)
        out: List[Dict[str, Any]] = []
        for s in items:
            try:
                if ":" in s:
                    pref_str, exch = s.split(":", 1)
                    out.append({"preference": int(pref_str), "exchange": exch.rstrip('.')})
                else:
                    out.append({"preference": None, "exchange": s.rstrip('.')})
            except Exception:
                out.append({"preference": None, "exchange": s})
        return out

    def _parse_srv_list(v: Any) -> List[Dict[str, Any]]:
        items = _split_tokens(v)
        out: List[Dict[str, Any]] = []
        for s in items:
            try:
                m = re.match(r"^(\d+)\s+(\d+)\s+(\d+)\s+([^\s]+)$", s)
                if m:
                    out.append({"priority": int(m.group(1)), "weight": int(m.group(2)),
                                "port": int(m.group(3)), "target": m.group(4).rstrip('.'),
                                "service": None, "proto": None, "ttl": None})
                else:
                    out.append({"priority": None, "weight": None, "port": None,
                                "target": s.rstrip('.'), "service": None, "proto": None, "ttl": None})
            except Exception:
                out.append({"priority": None, "weight": None, "port": None,
                            "target": s, "service": None, "proto": None, "ttl": None})
        return out

    def _parse_caa_list(v: Any) -> List[Dict[str, Any]]:
        items = _split_tokens(v)
        out: List[Dict[str, Any]] = []
        for s in items:
            try:
                m = re.match(r"^(\d+)\s+(\w+)\s+\"?(.*?)\"?$", s)
                if m:
                    out.append({"flags": int(m.group(1)), "tag": m.group(2), "value": m.group(3)})
                else:
                    out.append({"flags": None, "tag": "", "value": s})
            except Exception:
                out.append({"flags": None, "tag": "", "value": s})
        return out

    def _parse_naptr_list(v: Any) -> List[Dict[str, Any]]:
        items = _split_tokens(v)
        out: List[Dict[str, Any]] = []
        for s in items:
            try:
                m = re.match(r'^(\d+)\s+(\d+)\s+"(.*?)"\s+"(.*?)"\s+"(.*?)"\s+([^\s]+)$', s)
                if m:
                    out.append({"order": int(m.group(1)), "preference": int(m.group(2)),
                                "flags": m.group(3), "services": m.group(4),
                                "regexp": m.group(5), "replacement": m.group(6).rstrip('.')})
                else:
                    out.append({"order": None, "preference": None, "flags": "",
                                "services": "", "regexp": "", "replacement": s.rstrip('.')})
            except Exception:
                out.append({"order": None, "preference": None, "flags": "",
                            "services": "", "regexp": "", "replacement": s})
        return out

    return {
        "domain": str(getattr(rec, "domain", "") or ""),
        "status": str(getattr(rec, "status", "") or ""),
        "registered_domain": _join_list(g("registered_domain")),
        "ns": _join_list(g("ns") or g("ns1")),
        "ns_list": _split_tokens(g("ns") or g("ns1")),
        "soa": _join_list(g("soa")),
        "a": _join_list(g("a")),
        "a_list": _split_tokens(g("a")),
        "aaaa": _join_list(g("aaaa")),
        "aaaa_list": _split_tokens(g("aaaa")),
        "mx": _join_list(g("mx") or g("mail_mx")),
        "mx_records": _parse_mx_list(g("mx") or g("mail_mx")),
        "txt": _join_list(g("txt")),
        "txt_list": _split_tokens(g("txt")),
        "cname": _join_list(g("cname")),
        "caa": _join_list(g("caa")),
        "caa_records": (meta.get("caa_struct") if isinstance(meta.get("caa_struct"), list)
                        else getattr(rec, "caa_records", None)) or _parse_caa_list(g("caa")),
        "naptr": _join_list(g("naptr")),
        "naptr_records": (meta.get("naptr_struct") if isinstance(meta.get("naptr_struct"), list)
                          else getattr(rec, "naptr_records", None)) or _parse_naptr_list(g("naptr")),
        "srv": _join_list(g("srv")),
        "srv_records": getattr(rec, "srv_records", None) or _parse_srv_list(g("srv")),
        "a_ttl": meta.get("a_ttl") or getattr(rec, "a_ttl", None),
        "aaaa_ttl": meta.get("aaaa_ttl") or getattr(rec, "aaaa_ttl", None),
        "mx_ttl": meta.get("mx_ttl") or getattr(rec, "mx_ttl", None),
        "txt_ttl": meta.get("txt_ttl") or getattr(rec, "txt_ttl", None),
        "caa_ttl": meta.get("caa_ttl") or getattr(rec, "caa_ttl", None),
        "naptr_ttl": meta.get("naptr_ttl") or getattr(rec, "naptr_ttl", None),
        "ptr": _join_list(g("ptr")),
        "ptr_list": _split_tokens(g("ptr")),
        "www": _join_list(g("www")),
        "www_cname": _join_list(g("www_cname")),
        "mail_mx": _join_list(g("mail_mx")),
        "mx_host_final": _join_list(g("mx_host_final")),
        "mx_regdom_final": _join_list(g("mx_regdom_final") or g("mx_domain")),
        "mx_ips": _join_list(g("mx_ips")),
        "mx_ptr": _join_list(g("mx_ptr")),
        "mx_ptr_regdom": _join_list(g("mx_ptr_regdom")),
        "ns_ips": _join_list(g("ns_ips")),
        "ns_ip_int": getattr(rec, "ns_ip_int", None) or g("ns_ip_int"),
        "ns_ptr": _join_list(g("ns_ptr")),
        "ns_ptr_regdom": _join_list(g("ns_ptr_regdom")),
        "spf": _join_list(g("spf")),
        "dmarc": _join_list(g("dmarc")),
        "bimi": _join_list(g("bimi")),
        "www_a": _join_list(g("www_a")),
        "www_int": getattr(rec, "www_int", None) or g("www_int"),
        "www_ptr": _join_list(g("www_ptr")),
        "mail_a": _join_list(g("mail_a")),
        "mail_int": getattr(rec, "mail_int", None) or g("mail_int"),
        "mail_ptr": _join_list(g("mail_ptr")),
        "mail_cname": _join_list(g("mail_cname")),
        "mail_mx_domain": _join_list(g("mail_mx_domain")),
        "mail_mx_tld": _join_list(g("mail_mx_tld")),
        "mail_spf": _join_list(g("mail_spf")),
        "mail_dmarc": _join_list(g("mail_dmarc")),
        "mx_banner_raw": getattr(rec, "mx_banner_raw", "") or "",
        "mx_banner_host": getattr(rec, "mx_banner_host", "") or "",
        "mx_banner_details": getattr(rec, "mx_banner_details", "") or "",
        "mx_banner_provider": getattr(rec, "mx_banner_provider", "") or "",
        "mx_banner_category": getattr(rec, "mx_banner_category", "") or "",
        "has_mta_sts": bool(getattr(rec, "has_mta_sts", False)),
        "mta_sts_txt": getattr(rec, "mta_sts_txt", "") or "",
        "mta_sts_mode": getattr(rec, "mta_sts_mode", "") or "",
        "mta_sts_max_age": getattr(rec, "mta_sts_max_age", None),
        "mta_sts_id": getattr(rec, "mta_sts_id", "") or "",
        "tlsrpt_rua": getattr(rec, "tlsrpt_rua", "") or "",
        "smtp_cert_ok": getattr(rec, "smtp_cert_ok", None),
        "smtp_cert_days_left": getattr(rec, "smtp_cert_days_left", None),
        "smtp_cert_issuer": getattr(rec, "smtp_cert_issuer", "") or "",
        "https_cert_ok": getattr(rec, "https_cert_ok", None),
        "https_cert_days_left": getattr(rec, "https_cert_days_left", None),
        "https_cert_issuer": getattr(rec, "https_cert_issuer", "") or "",
        "https_cert_san_count": getattr(rec, "https_cert_san_count", None),
        "dnssec": bool(getattr(rec, "dnssec", False)),
        "soa_serial": getattr(rec, "soa_serial", None),
        "records_json": records_json,
        "errors_json": errors_json,
        "meta_json": meta_json,
    }


def get_dns_expanded_schema():
    return pa.schema([
        pa.field("domain", pa.string()),
        pa.field("source", pa.string()),
        pa.field("status", pa.string()),
        pa.field("timestamp", pa.float64()),
        pa.field("records_json", pa.string()),
        pa.field("registered_domain", pa.string()),
        pa.field("ns", pa.string()),
        pa.field("ns_list", pa.list_(pa.string())),
        pa.field("soa", pa.string()),
        pa.field("a", pa.string()),
        pa.field("a_list", pa.list_(pa.string())),
        pa.field("aaaa", pa.string()),
        pa.field("aaaa_list", pa.list_(pa.string())),
        pa.field("mx", pa.string()),
        pa.field("mx_records", pa.list_(pa.struct([
            pa.field("preference", pa.int32()),
            pa.field("exchange", pa.string()),
        ]))),
        pa.field("txt", pa.string()),
        pa.field("txt_list", pa.list_(pa.string())),
        pa.field("cname", pa.string()),
        pa.field("caa", pa.string()),
        pa.field("caa_records", pa.list_(pa.struct([
            pa.field("flags", pa.int32()),
            pa.field("tag", pa.string()),
            pa.field("value", pa.string()),
        ]))),
        pa.field("naptr", pa.string()),
        pa.field("naptr_records", pa.list_(pa.struct([
            pa.field("order", pa.int32()),
            pa.field("preference", pa.int32()),
            pa.field("flags", pa.string()),
            pa.field("services", pa.string()),
            pa.field("regexp", pa.string()),
            pa.field("replacement", pa.string()),
        ]))),
        pa.field("srv", pa.string()),
        pa.field("srv_records", pa.list_(pa.struct([
            pa.field("priority", pa.int32()),
            pa.field("weight", pa.int32()),
            pa.field("port", pa.int32()),
            pa.field("target", pa.string()),
            pa.field("service", pa.string()),
            pa.field("proto", pa.string()),
            pa.field("ttl", pa.int32()),
        ]))),
        pa.field("a_ttl", pa.int32()),
        pa.field("aaaa_ttl", pa.int32()),
        pa.field("mx_ttl", pa.int32()),
        pa.field("txt_ttl", pa.int32()),
        pa.field("caa_ttl", pa.int32()),
        pa.field("naptr_ttl", pa.int32()),
        pa.field("ptr", pa.string()),
        pa.field("ptr_list", pa.list_(pa.string())),
        pa.field("www", pa.string()),
        pa.field("www_cname", pa.string()),
        pa.field("mail_mx", pa.string()),
        pa.field("mx_host_final", pa.string()),
        pa.field("mx_regdom_final", pa.string()),
        pa.field("mx_ips", pa.string()),
        pa.field("mx_ptr", pa.string()),
        pa.field("mx_ptr_regdom", pa.string()),
        pa.field("ns_ips", pa.string()),
        pa.field("ns_ip_int", pa.int64()),
        pa.field("ns_ptr", pa.string()),
        pa.field("ns_ptr_regdom", pa.string()),
        pa.field("spf", pa.string()),
        pa.field("dmarc", pa.string()),
        pa.field("bimi", pa.string()),
        pa.field("www_a", pa.string()),
        pa.field("www_int", pa.int64()),
        pa.field("www_ptr", pa.string()),
        pa.field("mail_a", pa.string()),
        pa.field("mail_int", pa.int64()),
        pa.field("mail_ptr", pa.string()),
        pa.field("mail_cname", pa.string()),
        pa.field("mail_mx_domain", pa.string()),
        pa.field("mail_mx_tld", pa.string()),
        pa.field("mail_spf", pa.string()),
        pa.field("mail_dmarc", pa.string()),
        pa.field("mx_banner_raw", pa.string()),
        pa.field("mx_banner_host", pa.string()),
        pa.field("mx_banner_details", pa.string()),
        pa.field("mx_banner_provider", pa.string()),
        pa.field("mx_banner_category", pa.string()),
        pa.field("has_mta_sts", pa.bool_()),
        pa.field("mta_sts_txt", pa.string()),
        pa.field("mta_sts_mode", pa.string()),
        pa.field("mta_sts_max_age", pa.int64()),
        pa.field("mta_sts_id", pa.string()),
        pa.field("tlsrpt_rua", pa.string()),
        pa.field("smtp_cert_ok", pa.bool_()),
        pa.field("smtp_cert_days_left", pa.int32()),
        pa.field("smtp_cert_issuer", pa.string()),
        pa.field("https_cert_ok", pa.bool_()),
        pa.field("https_cert_days_left", pa.int32()),
        pa.field("https_cert_issuer", pa.string()),
        pa.field("https_cert_san_count", pa.int32()),
        pa.field("dnssec", pa.bool_()),
        pa.field("soa_serial", pa.int64()),
        pa.field("errors_json", pa.string()),
        pa.field("meta_json", pa.string()),
    ])


class BatchProcessor:
    def __init__(
        self,
        file_key: str,
        output_dir: str,
        retry_dir: str,
        lookups_db_path: Optional[str] = None,
        flight_server_url: Optional[str] = None,
        workers: int = DEFAULT_WORKERS,
        semaphore: Optional[asyncio.Semaphore] = None,
        logger: Optional[Any] = None,
        lmdb_path: Optional[str] = None,
        retry_limit: int = 1,
        source_feed: str = "zone_file",
    ):
        self.file_key = file_key
        self.source_feed = source_feed
        self.output_dir = Path(output_dir)
        self.retry_dir = Path(retry_dir)
        self.retry_limit = retry_limit

        raw_lookups = lookups_db_path if lookups_db_path is not None else (NFS_BASE / "lookups")
        try:
            p = Path(str(raw_lookups))
            self.lookups_db_path = str(p) if p.suffix == ".duckdb" else str(p / "lookups.duckdb")
        except Exception:
            self.lookups_db_path = str(NFS_BASE / "lookups" / "lookups.duckdb")

        self.flight_server_url = flight_server_url

        try:
            env_workers = int(os.getenv("DNS_BATCH_WORKERS", "0"))
        except Exception:
            env_workers = 0
        self.workers = env_workers if env_workers > 0 else workers

        try:
            sem_limit = int(os.getenv("DNS_SEMAPHORE_LIMIT", "100"))
        except Exception:
            sem_limit = 100
        self.semaphore = semaphore or asyncio.Semaphore(max(1, sem_limit))

        if logger is None:
            try:
                self.log = log.bind(module="batch_processor", file_key=self.file_key) if hasattr(log, "bind") else log
            except Exception:
                self.log = log
        else:
            try:
                self.log = logger.bind(module="batch_processor", file_key=self.file_key) if hasattr(logger, "bind") else logger
            except Exception:
                self.log = log

        self.log.info("BatchProcessor initialized (file_key={}, workers={}, sem_limit={})",
                      self.file_key, self.workers, sem_limit)
        self.lmdb_path = lmdb_path
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.retry_dir.mkdir(parents=True, exist_ok=True)

    def _build_graph_tables(self, results: List[DNSRecord]) -> Tuple[pa.Table, pa.Table, pa.Table]:
        now = datetime.utcnow()
        domains_data, ips_data, edges_data = [], [], []
        seen_ips = set()

        for rec in results:
            domain_str = getattr(rec, "domain", "")
            if not domain_str:
                continue

            domain_id = hash_domain(domain_str)
            regdom = getattr(rec, "registered_domain", "") or domain_str

            domains_data.append({
                "domain_id": domain_id,
                "domain": domain_str.lower(),
                "apex": regdom.lower(),
                "tld": regdom.split('.')[-1] if '.' in regdom else "",
                "first_seen_ts": now,
                "last_seen_ts": now,
                "source_flags": json.dumps({"status": getattr(rec, "status", "")})
            })

            def _extract_ips(record_attr) -> List[str]:
                val = getattr(rec, record_attr, [])
                if not val:
                    return []
                if isinstance(val, str):
                    return val.split('|')
                return [str(x) for x in val if x]

            for ip_str in _extract_ips("a"):
                ip_str = ip_str.strip()
                if not ip_str:
                    continue
                ip_id = hash_ip(ip_str)
                if ip_id not in seen_ips:
                    ips_data.append({"ip_id": ip_id, "ip": ip_str, "ip_version": 4,
                                     "first_seen_ts": now, "last_seen_ts": now})
                    seen_ips.add(ip_id)
                edges_data.append({
                    "src_type": "domain", "src_id": domain_id,
                    "dst_type": "ip", "dst_id": ip_id, "edge_type": "A",
                    "first_seen_ts": now, "last_seen_ts": now, "last_observed_ts": now,
                    "attrs": json.dumps({"ttl": getattr(rec, "a_ttl", 300) or 300})
                })

            for ip_str in _extract_ips("aaaa"):
                ip_str = ip_str.strip()
                if not ip_str:
                    continue
                ip_id = hash_ip(ip_str)
                if ip_id not in seen_ips:
                    ips_data.append({"ip_id": ip_id, "ip": ip_str, "ip_version": 6,
                                     "first_seen_ts": now, "last_seen_ts": now})
                    seen_ips.add(ip_id)
                edges_data.append({
                    "src_type": "domain", "src_id": domain_id,
                    "dst_type": "ip", "dst_id": ip_id, "edge_type": "AAAA",
                    "first_seen_ts": now, "last_seen_ts": now, "last_observed_ts": now,
                    "attrs": json.dumps({"ttl": getattr(rec, "aaaa_ttl", 300) or 300})
                })

        return (
            pa.Table.from_pylist(domains_data, schema=get_graph_domain_schema()),
            pa.Table.from_pylist(ips_data, schema=get_graph_ip_schema()),
            pa.Table.from_pylist(edges_data, schema=get_graph_edge_schema()),
        )

    async def write_flight(self, table: pa.Table, dataset_name: str):
        def _do_write():
            client = flight.FlightClient(self.flight_server_url)
            descriptor = flight.FlightDescriptor.for_path(dataset_name)
            writer, _ = client.do_put(descriptor, table.schema)
            writer.write_table(table)
            writer.close()
        await asyncio.to_thread(_do_write)
        self.log.info(f"Streamed {dataset_name} to Flight Server at {self.flight_server_url}")

    async def write_output(self, table: pa.Table, path: str | Path, dataset_name: str):
        if self.flight_server_url:
            try:
                await self.write_flight(table, dataset_name)
                return
            except Exception as e:
                self.log.error(f"Flight stream failed for {dataset_name}: {e}. Falling back to Parquet...")
        await asyncio.to_thread(pq.write_table, table, str(path))
        self.log.info(f"Written to {path}")

    async def write_parquet(self, table: pa.Table, path: str | Path):
        await asyncio.to_thread(pq.write_table, table, str(path))
        self.log.info(f"Written to {path}")

    async def process(
        self,
        domains: Iterable[str],
        retry_limit: Optional[int] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Process a batch of domains.

        Workflow:
        1. fetch_batch — DNS lookups
        2. Build signature_rows for delta detection
        3. annotate_change_flags_arrow — LMDB delta check (readonly)
        4. Write retries snapshot
        5. Build and write expanded parquet (main corpus → Flight → master)
        6. Build and write graph tables (entity_domain, entity_ip, entity_edge)
        7. Write retries parquet
        8. Return (expanded_path, retries_path)

        Note: dns_results removed — master updates LMDB from dns_expanded via Flight.
        """
        active_retry_limit = self.retry_limit if retry_limit is None else retry_limit
        start_time = time.time()
        domain_list = list(domains)
        domain_count = len(domain_list)

        self.log.info(
            f"Starting batch processing: {domain_count} domains, "
            f"{self.workers} workers, file_key={self.file_key}, retry_limit={active_retry_limit}"
        )

        # Step 1: Fetch DNS records
        results, retries = await fetch_batch(
            domain_list,
            semaphore=self.semaphore,
            workers=self.workers,
            retry_limit=active_retry_limit
        )

        self.log.info(f"Fetch complete: {len(results)} results, {len(retries)} retries")

        # Step 2: Build signature rows for delta detection
        signature_rows: List[Dict[str, Any]] = []
        for rec in results:
            try:
                domain = str(getattr(rec, "domain", "") or "").lower()
                status = str(getattr(rec, "status", "") or "")
                regdom_val = str(getattr(rec, "registered_domain", "") or "").lower()

                row = {
                    "domain": domain,
                    "status": status,
                    "registered_domain": regdom_val,
                }

                records_dict = getattr(rec, "records", None)
                if not isinstance(records_dict, dict):
                    records_dict = {}
                    for field_name in [
                        "ns", "ns1", "a", "aaaa", "mx", "txt", "cname", "soa", "srv",
                        "naptr", "caa", "ptr", "spf", "dmarc", "bimi",
                        "www", "www_cname", "www_a", "www_ptr",
                        "mail_a", "mail_mx", "mail_spf", "mail_dmarc", "mail_cname",
                        "mail_mx_domain", "mail_mx_tld",
                        "mx_domain", "mx_host_final", "mx_regdom_final"
                    ]:
                        val = getattr(rec, field_name, None)
                        if val is not None:
                            records_dict[field_name] = val
                    for ttl_field in ["a_ttl", "aaaa_ttl", "mx_ttl", "txt_ttl", "caa_ttl", "naptr_ttl"]:
                        val = getattr(rec, ttl_field, None)
                        if val is not None:
                            row[ttl_field] = val

                def g(key: str) -> Any:
                    return records_dict.get(key)

                ns_candidate = g("ns") or g("ns1")
                row["ns"] = _normalize_ns_value(ns_candidate)
                row["ns_raw"] = _join_list(ns_candidate)
                row["ns_list_norm"] = _normalize_ns_list(ns_candidate)

                a_candidate = g("a")
                row["a"] = _join_list(a_candidate)

                first_ip = ""
                if isinstance(a_candidate, list):
                    first_ip = next((str(x) for x in a_candidate if isinstance(x, str) and x), "")
                elif isinstance(a_candidate, str):
                    first_ip = a_candidate.split("|")[0] if a_candidate else ""

                ip_int_val = getattr(rec, "ip_int", None)
                if ip_int_val is None and first_ip:
                    try:
                        ip_int_val = ip_to_int(first_ip)
                    except Exception:
                        ip_int_val = None
                row["ip_int"] = ip_int_val

                row["aaaa"] = _join_list(g("aaaa"))
                row["soa"] = _join_list(g("soa"))
                row["ptr"] = _join_list(g("ptr"))
                row["cname"] = _join_list(g("cname"))
                row["txt"] = _join_list(g("txt"))
                row["spf"] = _join_list(g("spf"))
                row["dmarc"] = _join_list(g("dmarc"))
                row["bimi"] = _join_list(g("bimi"))
                row["caa"] = _join_list(g("caa"))
                row["srv"] = _join_list(g("srv"))
                row["naptr"] = _join_list(g("naptr"))
                row["mx_host_norm"] = _join_list(g("mx_host_final") or g("mx") or g("mail_mx"))
                row["mx_regdom_norm"] = _join_list(g("mx_regdom_final") or g("mx_domain"))
                row["mx_regdom_final"] = _join_list(g("mx_regdom_final") or g("mx_domain"))
                row["mx"] = _join_list(g("mx"))
                row["mx_domain"] = _join_list(g("mx_domain"))
                row["mx_host_final"] = _join_list(g("mx_host_final"))
                row["mx_ips"] = _join_list(g("mx_ips"))
                row["mx_ptr"] = _join_list(g("mx_ptr"))
                row["ns_host_final"] = _join_list(g("ns_host_final"))
                row["ns_regdom_final"] = _join_list(g("ns_regdom_final"))
                row["ns_ips"] = _join_list(g("ns_ips"))
                row["ns_ptr"] = _join_list(g("ns_ptr"))
                row["ns_ptr_regdom"] = _join_list(g("ns_ptr_regdom"))

                ns_ip_int_val = getattr(rec, "ns_ip_int", None)
                if ns_ip_int_val is None and g("ns_ips"):
                    ns_ips_list = g("ns_ips")
                    first_ns_ip = ns_ips_list[0] if isinstance(ns_ips_list, list) and ns_ips_list else ""
                    if first_ns_ip:
                        try:
                            ns_ip_int_val = ip_to_int(first_ns_ip)
                        except Exception:
                            pass
                row["ns_ip_int"] = ns_ip_int_val

                row["www"] = _join_list(g("www"))
                row["www_cname"] = _join_list(g("www_cname"))
                row["www_a"] = _join_list(g("www_a"))
                row["www_ptr"] = _join_list(g("www_ptr"))
                row["mail_a"] = _join_list(g("mail_a"))
                row["mail_mx"] = _join_list(g("mail_mx"))
                row["mail_cname"] = _join_list(g("mail_cname"))
                row["mail_spf"] = _join_list(g("mail_spf"))
                row["mail_dmarc"] = _join_list(g("mail_dmarc"))

                for ttl_attr in ["a_ttl", "aaaa_ttl", "mx_ttl", "txt_ttl", "caa_ttl", "naptr_ttl"]:
                    if ttl_attr not in row:
                        val = getattr(rec, ttl_attr, None)
                        if val is not None:
                            row[ttl_attr] = val

                signature_rows.append(row)
            except Exception as e:
                self.log.error(f"Failed to build signature row for {getattr(rec, 'domain', '<unknown>')}: {e}")

        # Step 3: Delta detection — single LMDB open, used once, closed cleanly
        if not self.lmdb_path:
            raise RuntimeError("LMDB path not configured on BatchProcessor")

        with LMDBActivity(str(self.lmdb_path), readonly=True) as kv:
            change_table, deltas = annotate_change_flags_arrow(
                signature_rows,
                kv,
                domain_col="domain",
                ns_col="ns_raw",
                a_col="a",
                mx_regdom_col="mx_regdom_final",
                status_col="status",
                mx_ips_col="mx_ips",
            )
        # kv is now closed — do not reference it again

        # Emit deltas for the master aggregator
        delta_path = str(NFS_BASE / "deltas" / f"delta_{self.file_key}.csv")
        write_activity_delta_csv(deltas, delta_path)

        # Step 4: Write initial retries snapshot
        if retries:
            initial_retries_path = self.retry_dir / f"{self.file_key}_initial_retries.parquet"
            initial_retries_table = self.join_tables(retries)
            await self.write_parquet(initial_retries_table, initial_retries_path)
            self.log.info(f"Wrote initial retries snapshot to {initial_retries_path}")

        # Step 5: Build and write expanded parquet (main corpus)
        # This is sent via Flight to master which updates LMDB from dns_expanded
        expanded_path = self.output_dir / f"{self.file_key}_expanded.parquet"
        try:
            expanded_rows = []
            for rec in results:
                try:
                    row = _dnsrecord_to_expanded_row(rec)
                    row["source"] = getattr(self, "source_feed", "zone_file")
                    row["timestamp"] = time.time()
                    expanded_rows.append(row)
                except Exception:
                    expanded_rows.append({
                        "domain": str(getattr(rec, "domain", "") or ""),
                        "source": getattr(self, "source_feed", "zone_file"),
                        "status": str(getattr(rec, "status", "") or "error"),
                        "timestamp": time.time(),
                        "registered_domain": "", "ns": "", "soa": "", "a": "",
                        "aaaa": "", "mx": "", "txt": "", "cname": "", "caa": "",
                        "naptr": "", "srv": "", "ptr": "", "www": "", "www_cname": "",
                        "mail_mx": "", "mx_host_final": "", "mx_regdom_final": "",
                        
                        "spf": "", "dmarc": "", "bimi": "", "www_a": "", "www_int": None, 
                        "www_ptr": "", "mail_a": "", "mail_int": None, "mail_ptr": "", 
                        "mail_cname": "", "mail_mx_domain": "", "mail_mx_tld": "", 
                        "mail_spf": "", "mail_dmarc": "", "mx_banner_raw": "", 
                        "mx_banner_host": "", "mx_banner_details": "", "mx_banner_provider": "", 
                        "mx_banner_category": "", "has_mta_sts": False, "mta_sts_txt": "", 
                        "mta_sts_mode": "", "mta_sts_max_age": None, "mta_sts_id": "", 
                        "tlsrpt_rua": "", "smtp_cert_ok": None, "smtp_cert_days_left": None, 
                        "smtp_cert_issuer": "", "https_cert_ok": None, "https_cert_days_left": None, 
                        "https_cert_issuer": "", "https_cert_san_count": None, "dnssec": False, 
                        "soa_serial": None,
                        
                        "errors_json": "{}", "meta_json": "{}",
                    })
            expanded_table = pa.Table.from_pylist(expanded_rows, schema=get_dns_expanded_schema())
            # Isolate threat feeds to their own dataset to avoid mingling with standard 320M domains
            out_dataset = "hourly_threat" if "prio_" in self.file_key.lower() else "dns_expanded"
            await self.write_output(expanded_table, expanded_path, out_dataset)
            self.log.info("Expanded table written: rows={}, dataset={}", len(expanded_rows), out_dataset)
        except Exception as e:
            self.log.error("Failed to write expanded table: {}", e, exc_info=True)
            raise

        # Step 6: Legacy Graph tables deprecated in favor of fully amalgamated 'domain_expanded' DataLake.

        # Step 7: Write retries parquet
        retries_path = None
        retry_rows = []
        for rec in retries:
            try:
                retry_rows.append(_dnsrecord_to_row(rec))
            except Exception as e:
                self.log.error(f"Failed to serialize retry for {rec.domain}: {e}", exc_info=True)
                retry_rows.append({
                    "domain": rec.domain, "status": "needs_retry",
                    "records_json": "{}", "errors_json": json.dumps({"serialization": str(e)}),
                    "meta_json": "{}",
                })

        if retry_rows:
            retries_path = self.retry_dir / f"{self.file_key}_retries.parquet"
            try:
                retries_table = pa.Table.from_pylist(retry_rows, schema=get_dns_schema())
                pq.write_table(retries_table, retries_path)
                self.log.info(f"Wrote {len(retry_rows)} retries to {retries_path}")
            except Exception as e:
                self.log.error(f"Failed to write retries parquet: {e}", exc_info=True)
                raise

        # Step 8: Throughput metrics
        elapsed = time.time() - start_time
        throughput = domain_count / elapsed if elapsed > 0 else 0
        self.log.info(
            f"Batch complete: {domain_count} domains in {elapsed:.2f}s "
            f"({throughput:.1f} domains/s)"
        )

        return str(expanded_path), str(retries_path) if retries_path else None

    def join_tables(self, dns_records: List[DNSRecord]) -> pa.Table:
        """Convert DNSRecord list to compact PyArrow table — used for retries."""
        rows = []
        for rec in dns_records:
            try:
                rows.append(_dnsrecord_to_row(rec))
            except Exception as e:
                self.log.error(f"Failed to convert DNSRecord for {rec.domain}: {e}", exc_info=True)
                rows.append({
                    "domain": getattr(rec, "domain", "<unknown>"),
                    "status": "error", "records_json": "{}",
                    "errors_json": json.dumps({"serialization": str(e)}),
                    "meta_json": "{}",
                })
        try:
            return pa.Table.from_pylist(rows, schema=get_dns_schema())
        except Exception as e:
            self.log.error(f"Failed to build pyarrow table: {e}", exc_info=True)
            return pa.Table.from_pylist([], schema=get_dns_schema())
