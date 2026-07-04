"""
master_flight_server_patched.py

Arrow Flight ingestion server with two-speed write architecture:

  BATCH PATH  (DNS + entity data)
    Workers → Flight → per-dataset Accumulator → Parquet staging files
    Promotion job reads staging files → scores in DB → silver layer

  REALTIME PATH (CertStream)
    CT log events → Flight → RealtimeBuffer → DuckDB direct insert
    Flushes on 50k events OR 30 seconds, whichever comes first

Scoring is entirely DB-side during promotion — not in this server.

LMDB signature updates:
    dns_expanded flush → _update_lmdb_signatures()
    Master is the sole LMDB writer; workers open LMDB readonly only.
"""

import duckdb
import ipaddress
import json
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
env_path = Path(__file__).resolve().parent.parent.parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)

R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID")
R2_ACCESS_KEY = os.environ.get("R2_ACCESS_KEY")
R2_SECRET_KEY = os.environ.get("R2_SECRET_KEY")
R2_BUCKET = os.getenv("R2_DOMAINS_BUCKET", "domains-monitor")

import pyarrow as pa
import pyarrow.flight as flight
import pyarrow.parquet as pq

# LMDB signature store — master is the sole writer
sys.path.insert(0, "/root/dnsproject")
from kv.lmdb_store import LMDBActivity

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("flight_server")

LMDB_PATH = "/srv/nfs/shared/dns_lmdb"
LMDB_UPDATE_DATASETS = {"dns_expanded", "hourly_threat"}

# --- ADDED `new_domains`, `subdomains`, AND `anomalies` TO THE REALTIME DATASETS TRACKER ---
REALTIME_DATASETS = {"certstream_raw", "new_domains", "subdomains", "anomalies", "platform_hits", "burst_anomalies"}

STAGING_TARGET_MB = 128
STAGING_MAX_AGE_SECONDS = 300
CERTSTREAM_MAX_RECORDS = 50_000
CERTSTREAM_MAX_AGE_SECONDS = 30

# #4 — shared IP→ASN/risk lookup. The master is the hub dnsproject talks to, so it
# holds gold.asn_ip4 (the full IPv4 routing table) + risk feeds in memory ONCE and
# resolves cold IPs for clients (brand_orchestrator/LakeEnricher) over Flight —
# instead of each client querying DuckLake-over-R2 per alert or loading the huge
# routing table into its own RAM. Sources are the gold parquets already synced to
# the master for the edge-sync endpoints; override via env if they live elsewhere.
ASN_IP4_PARQUET = os.environ.get("ASN_IP4_PARQUET", "/root/dnsall/asn_ip4_latest.parquet")
RISK_ASN_PARQUET = os.environ.get("RISK_ASN_PARQUET", "/root/dnsall/gold_risk_asn_latest.parquet")
RISK_PREFIX_PARQUET = os.environ.get("RISK_PREFIX_PARQUET", "/root/dnsall/gold_risk_prefix_latest.parquet")
# Also served per-IP so BOTH the alert path AND the health report stop scanning these
# range tables over R2 (the health-report OOM source).
CLOUD_RANGES_PARQUET = os.environ.get("CLOUD_RANGES_PARQUET", "/root/dnsall/cloud_ranges_latest.parquet")
IP_RISK_PARQUET = os.environ.get("IP_RISK_PARQUET", "/root/dnsall/ip_risk_latest.parquet")


def _ip_to_int(ip):
    try:
        a = ipaddress.ip_address(ip)
        return int(a) if a.version == 4 else None
    except ValueError:
        return None

def _update_lmdb_signatures(table: pa.Table) -> None:
    required = {"domain", "ns", "a", "mx_ips", "registered_domain"}
    present = set(table.schema.names)
    if not required.issubset(present):
        log.warning(f"LMDB update skipped — missing columns: {required - present}")
        return
    rows = table.to_pylist()
    updated = 0
    skipped = 0
    try:
        with LMDBActivity(LMDB_PATH, readonly=False) as kv:
            for row in rows:
                try:
                    domain = row.get("domain")
                    if not domain:
                        continue
                    sig = LMDBActivity.compute_signature_dict({
                        "ns":                row.get("ns", ""),
                        "a":                 row.get("a", ""),
                        "mx_regdom":         row.get("mx_regdom_final") or row.get("mx_domain", ""),
                        "registered_domain": row.get("registered_domain", ""),
                        "mx_ips":            row.get("mx_ips", ""),
                    })
                    if kv.changed(domain, sig):
                        kv.set_sig(domain, sig)
                        updated += 1
                    else:
                        skipped += 1
                except Exception as e:
                    log.debug(f"LMDB sig update failed for {row.get('domain')}: {e}")
    except Exception as e:
        log.error(f"LMDB signature update failed: {e}")
        return
    log.info(f"LMDB signatures: {updated} updated, {skipped} unchanged out of {len(rows)} rows")

@dataclass
class DatasetAccumulator:
    dataset_name: str
    staging_dir: Path
    target_bytes: int
    max_age_seconds: int

    _batches: list = field(default_factory=list)
    _accumulated_bytes: int = field(default=0)
    _last_flush_time: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _files_written: int = field(default=0)

    def push(self, batch: pa.RecordBatch) -> bool:
        with self._lock:
            self._batches.append(batch)
            self._accumulated_bytes += batch.nbytes
            if self._accumulated_bytes >= self.target_bytes:
                self._flush()
                return True
        return False

    def flush_if_stale(self):
        with self._lock:
            age = time.time() - self._last_flush_time
            if self._batches and age >= self.max_age_seconds:
                log.info(
                    f"[{self.dataset_name}] Watchdog flush — "
                    f"{len(self._batches)} batches aged {age:.0f}s"
                )
                self._flush()

    def _flush(self):
        if not self._batches:
            return
        mb = self._accumulated_bytes / (1024 * 1024)
        ts_ms = int(time.time() * 1000)

        # Same mixed-schema handling as RealtimeBuffer: during a rolling worker
        # deploy that widens a dataset (e.g. dns_expanded 50→83 cols), one buffer
        # window holds both widths. Without this, from_batches raises ArrowInvalid
        # and — because the buffer was only cleared after a successful write —
        # every later flush re-failed on the same stuck batches, wedging the
        # dataset and growing memory until restart.
        table = None
        try:
            table = pa.Table.from_batches(self._batches)
        except pa.ArrowInvalid:
            try:
                tables = [pa.Table.from_batches([b]) for b in self._batches]
                try:
                    table = pa.concat_tables(tables, promote_options="permissive")
                except TypeError:  # pyarrow < 14
                    table = pa.concat_tables(tables, promote=True)
                log.warning(
                    f"[{self.dataset_name}] Unified {len(tables)} mixed-schema batches "
                    f"in staging buffer (upstream schema change)"
                )
            except Exception as e:
                log.warning(
                    f"[{self.dataset_name}] Could not unify mixed schemas ({e}); "
                    f"flushing batches individually"
                )

        try:
            if table is not None:
                filename = f"{self.dataset_name}_{ts_ms}.parquet"
                pq.write_table(table, self.staging_dir / filename, compression="zstd", row_group_size=50_000)
                self._files_written += 1
                log.info(f"[{self.dataset_name}] → {filename} | {len(table):,} rows | {mb:.1f}MB uncompressed | file #{self._files_written}")
                if self.dataset_name in LMDB_UPDATE_DATASETS:
                    _update_lmdb_signatures(table)
            else:
                for idx, batch in enumerate(self._batches):
                    try:
                        batch_table = pa.Table.from_batches([batch])
                        filename = f"{self.dataset_name}_{ts_ms}_{idx}.parquet"
                        pq.write_table(batch_table, self.staging_dir / filename, compression="zstd", row_group_size=50_000)
                        self._files_written += 1
                        if self.dataset_name in LMDB_UPDATE_DATASETS:
                            _update_lmdb_signatures(batch_table)
                    except Exception as batch_exc:
                        log.error(f"[{self.dataset_name}] Failed flushing batch {idx}: {batch_exc}")
        finally:
            # Always clear — retaining failed batches wedges the dataset forever
            # and leaks memory. Tradeoff: a write failure (e.g. disk full) loses
            # that buffer window; acceptable vs. wedging all future flushes.
            self._batches.clear()
            self._accumulated_bytes = 0
            self._last_flush_time = time.time()

class RealtimeBuffer:
    def __init__(self, conn: duckdb.DuckDBPyConnection, dataset_name: str, max_records: int = CERTSTREAM_MAX_RECORDS, max_age_seconds: int = CERTSTREAM_MAX_AGE_SECONDS):
        self.conn = conn
        self.dataset_name = dataset_name
        self.max_records = max_records
        self.max_age_seconds = max_age_seconds
        self._buffer: list[pa.RecordBatch] = []
        self._row_count = 0
        self._last_flush = time.time()
        self._lock = threading.Lock()
        self._start_watchdog()

    def push(self, batch: pa.RecordBatch):
        with self._lock:
            self._buffer.append(batch)
            self._row_count += len(batch)
            if self._row_count >= self.max_records:
                self._flush()

    def flush_if_stale(self):
        with self._lock:
            age = time.time() - self._last_flush
            if self._buffer and age >= self.max_age_seconds:
                self._flush()

    def _flush(self):
        if not self._buffer:
            return

        staging_dir = Path("/root/certstream_stage") / self.dataset_name
        staging_dir.mkdir(parents=True, exist_ok=True)

        ts_ms = int(time.time() * 1000)

        # Build a single table. If the buffer holds mixed schemas (e.g. raw 5-col +
        # resolved rich-col subdomains), unify them by name (missing columns → null)
        # into one parquet instead of emitting many small per-batch files.
        table = None
        try:
            table = pa.Table.from_batches(self._buffer)
        except pa.ArrowInvalid:
            try:
                tables = [pa.Table.from_batches([b]) for b in self._buffer]
                try:
                    table = pa.concat_tables(tables, promote_options="permissive")
                except TypeError:  # pyarrow < 14
                    table = pa.concat_tables(tables, promote=True)
                log.warning(
                    f"[{self.dataset_name}] Unified {len(tables)} mixed-schema batches "
                    f"in realtime buffer (upstream schema drift)"
                )
            except Exception as e:
                log.warning(
                    f"[{self.dataset_name}] Could not unify mixed schemas ({e}); "
                    f"flushing batches individually"
                )

        try:
            if table is not None:
                filepath = staging_dir / f"{self.dataset_name}_{ts_ms}.parquet"
                pq.write_table(table, filepath, compression="zstd")
                log.info(f"[{self.dataset_name}] Realtime flush → {len(table):,} rows → {filepath}")
            else:
                for idx, batch in enumerate(self._buffer):
                    try:
                        batch_table = pa.Table.from_batches([batch])
                        filepath = staging_dir / f"{self.dataset_name}_{ts_ms}_{idx}.parquet"
                        pq.write_table(batch_table, filepath, compression="zstd")
                    except Exception as batch_exc:
                        log.error(f"[{self.dataset_name}] Failed flushing batch {idx}: {batch_exc}")
        except Exception as e:
            log.error(f"[{self.dataset_name}] Realtime flush failed: {e}")
        finally:
            self._buffer.clear()
            self._row_count = 0
            self._last_flush = time.time()

    def _start_watchdog(self):
        def watch():
            while True:
                time.sleep(5)
                self.flush_if_stale()
        threading.Thread(target=watch, daemon=True).start()

class GraphIngestServer(flight.FlightServerBase):
    def __init__(self, location, staging_dir="/root/staging"):
        super().__init__(location)
        self.staging_dir = Path(staging_dir)
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        
        # 100% In-Memory database! Absolutely zero file locks forever.
        self.conn = duckdb.connect()
        # Guardrail: cap DuckDB RAM so a leak/regression can never consume the whole
        # host again. The previous write-only {dataset}_raw accumulation grew
        # unbounded to ~11GB and pushed the box into swap; normal streaming queries
        # here stay well under this ceiling.
        try:
            self.conn.execute("SET memory_limit='8GB'")
        except Exception as e:
            log.warning(f"Could not set DuckDB memory_limit: {e}")

        if R2_ACCESS_KEY and R2_SECRET_KEY and R2_ACCOUNT_ID:
            try:
                self.conn.execute(f"""
                    CREATE SECRET IF NOT EXISTS r2_creds (
                        TYPE S3,
                        KEY_ID '{R2_ACCESS_KEY}',
                        SECRET '{R2_SECRET_KEY}',
                        ENDPOINT '{R2_ACCOUNT_ID}.r2.cloudflarestorage.com',
                        URL_STYLE 'path'
                    );
                """)
                log.info("🔐 R2 DuckDB S3-compatible secret configured with path-style URLs")
            except Exception as e:
                log.error(f"Failed to configure R2 secret: {e}")
                
        self._init_schema()
        self._accumulators: dict[str, DatasetAccumulator] = {}
        self._accumulator_lock = threading.Lock()
        self._realtime_buffers: dict[str, RealtimeBuffer] = {}
        # Dedicated connection for the IP-lookup endpoint (#4), separate from the
        # ingestion conn so per-lookup temp-table registration can't contend with
        # the realtime/streaming queries. Lazily populated on first lookup.
        self._lookup_con = None
        self._lookup_lock = threading.Lock()
        self._start_watchdog()
        log.info(f"✅ Flight server ready (Zero Locks) | staging={staging_dir} | lmdb={LMDB_PATH}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE SCHEMA IF NOT EXISTS stage;

            CREATE TABLE IF NOT EXISTS stage.certstream_raw (
                domain          VARCHAR,
                san_domains     VARCHAR[],
                issuer          VARCHAR,
                not_before      TIMESTAMP,
                not_after       TIMESTAMP,
                fingerprint     VARCHAR,
                seen_at         TIMESTAMP,
                ingested_at     TIMESTAMP
            );
            
            -- ADDED: Schema for our fast `new_domains` Bloom filter feeder
            -- Columns mirror the Arrow payload streamed by flight_dispatcher.py
            -- (domain, root, authority, capture_timestamp, raw_metadata).
            CREATE TABLE IF NOT EXISTS stage.new_domains (
                domain VARCHAR PRIMARY KEY,
                root VARCHAR,
                authority VARCHAR,
                capture_timestamp DOUBLE,
                raw_metadata VARCHAR,
                ingested_at TIMESTAMP
            );
        """)

    def _get_accumulator(self, dataset_name: str) -> DatasetAccumulator:
        with self._accumulator_lock:
            if dataset_name not in self._accumulators:
                self._accumulators[dataset_name] = DatasetAccumulator(
                    dataset_name=dataset_name,
                    staging_dir=self.staging_dir,
                    target_bytes=STAGING_TARGET_MB * 1024 * 1024,
                    max_age_seconds=STAGING_MAX_AGE_SECONDS,
                )
            return self._accumulators[dataset_name]

    def _get_realtime_buffer(self, dataset_name: str) -> RealtimeBuffer:
        if dataset_name not in self._realtime_buffers:
            self._realtime_buffers[dataset_name] = RealtimeBuffer(
                conn=self.conn,
                dataset_name=dataset_name,
            )
            log.info(f"[{dataset_name}] Realtime buffer initialised")
        return self._realtime_buffers[dataset_name]

    def _ensure_lookup(self):
        """Lazily build the in-memory IP-lookup DB (one shared copy for all clients)."""
        if self._lookup_con is not None:
            return self._lookup_con
        with self._lookup_lock:
            if self._lookup_con is not None:
                return self._lookup_con
            con = duckdb.connect()
            try:
                con.execute(f"SET memory_limit='{os.environ.get('LOOKUP_MEMORY_LIMIT', '4GB')}'")
                con.execute(f"SET threads={os.environ.get('LOOKUP_THREADS', '4')}")
            except Exception as e:
                log.warning(f"lookup DuckDB resource limit set failed: {e}")

            # The master's local /root/dnsall copies are STALE — the fresh gold tables
            # live on the riskscore box and in the DuckLake catalog. So load each table
            # from DuckLake by DEFAULT (LOOKUP_PREFER_LAKE=1); set it to 0 only on a host
            # that has fresh local parquets. Lake creds come from /root/dnsproject/.env
            # via the shared lake_connect(). One-time read into memory at first lookup.
            prefer_lake = os.environ.get("LOOKUP_PREFER_LAKE", "1") != "0"
            lake_con = None

            def _lake():
                nonlocal lake_con
                if lake_con is None:
                    dns_path = os.environ.get("DNSPROJECT_PATH", "/root/dnsproject")
                    if dns_path not in sys.path:
                        sys.path.insert(0, dns_path)
                    from scripts.lake_enrich import lake_connect
                    lake_con = lake_connect()
                return lake_con

            def _load(table, parquet, cols, empty_ddl, lake_fqtn):
                if not prefer_lake:
                    try:
                        con.execute(f"CREATE TABLE {table} AS SELECT {cols} FROM read_parquet('{parquet}')")
                        return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0], "local"
                    except Exception:
                        pass
                try:
                    arrow = _lake().execute(f"SELECT {cols} FROM {lake_fqtn}").arrow()
                    con.register("_src", arrow)
                    con.execute(f"CREATE TABLE {table} AS SELECT * FROM _src")
                    con.unregister("_src")
                    return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0], "lake"
                except Exception as e:
                    src = "lake" if prefer_lake else "local+lake"
                    log.warning(f"lookup: {table} unavailable ({src}): {e}; creating empty")
                    con.execute(empty_ddl)
                    return 0, "empty"

            n, src = _load(
                "asn_ip4", ASN_IP4_PARQUET,
                "start_int, end_int, asn, isp, isp_country, asn_risk_level, prefix",
                "CREATE TABLE asn_ip4(start_int BIGINT, end_int BIGINT, asn BIGINT, isp VARCHAR, "
                "isp_country VARCHAR, asn_risk_level VARCHAR, prefix VARCHAR)", "gold.asn_ip4")
            _load("gold_risk_asn", RISK_ASN_PARQUET, "asn, core_risk, reason_codes",
                  "CREATE TABLE gold_risk_asn(asn BIGINT, core_risk DOUBLE, reason_codes VARCHAR)",
                  "gold.gold_risk_asn")
            _load("gold_risk_prefix", RISK_PREFIX_PARQUET, "prefix, infra_score, reason_codes",
                  "CREATE TABLE gold_risk_prefix(prefix VARCHAR, infra_score DOUBLE, reason_codes VARCHAR)",
                  "gold.gold_risk_prefix")
            _load("cloud_ranges", CLOUD_RANGES_PARQUET, "provider, class, family, start_int, end_int",
                  "CREATE TABLE cloud_ranges(provider VARCHAR, class VARCHAR, family INTEGER, "
                  "start_int BIGINT, end_int BIGINT)", "ref.cloud_ranges")
            _load("ip_risk", IP_RISK_PARQUET, "risk_score, risk_reason, start_int, end_int",
                  "CREATE TABLE ip_risk(risk_score DOUBLE, risk_reason VARCHAR, start_int BIGINT, end_int BIGINT)",
                  "ref.ip_risk")

            if lake_con is not None:
                try:
                    lake_con.close()
                except Exception:
                    pass

            self._lookup_con = con
            log.info(f"🗺️  IP-lookup DB loaded: {n:,} asn_ip4 ranges in memory (asn_ip4 src={src})")
            return self._lookup_con

    def _lookup_ips(self, ips):
        """Resolve a batch of IPs → asn/isp/asn_risk_level/infra_score/reason_codes via
        the in-memory routing table. Returns an Arrow table (one row per input IPv4
        that mapped to a range)."""
        con = self._ensure_lookup()
        pairs = [(ip, _ip_to_int(ip)) for ip in ips]
        pairs = [(ip, n) for ip, n in pairs if n is not None]
        if not pairs:
            return pa.table({"ip": pa.array([], pa.string())})
        q = pa.table({"ip": pa.array([p[0] for p in pairs], pa.string()),
                      "n": pa.array([p[1] for p in pairs], pa.int64())})
        con.register("q", q)
        try:
            return con.execute(
                """
                WITH base AS (
                    SELECT q.ip, q.n, a.asn, a.isp, a.isp_country, a.asn_risk_level, a.prefix,
                           ga.core_risk, ga.reason_codes AS asn_reasons,
                           gp.infra_score AS prefix_infra, gp.reason_codes AS prefix_reasons,
                           row_number() OVER (PARTITION BY q.ip
                               ORDER BY COALESCE(gp.infra_score,0) DESC, COALESCE(ga.core_risk,0) DESC) AS rn
                    FROM q
                    LEFT JOIN asn_ip4 a ON q.n BETWEEN a.start_int AND a.end_int
                    LEFT JOIN gold_risk_asn ga ON ga.asn = a.asn
                    LEFT JOIN gold_risk_prefix gp ON gp.prefix = a.prefix
                )
                SELECT ip, asn, isp, isp_country, asn_risk_level, prefix,
                       core_risk, prefix_infra,
                       GREATEST(COALESCE(prefix_infra,0), COALESCE(core_risk,0)) AS infra_score,
                       asn_reasons, prefix_reasons,
                       (SELECT cr.provider FROM cloud_ranges cr WHERE cr.family=4
                          AND base.n BETWEEN cr.start_int AND cr.end_int
                          ORDER BY (cr.class='cdn') DESC, (cr.end_int - cr.start_int) ASC LIMIT 1) AS cloud_provider,
                       (SELECT cr.class FROM cloud_ranges cr WHERE cr.family=4
                          AND base.n BETWEEN cr.start_int AND cr.end_int
                          ORDER BY (cr.class='cdn') DESC, (cr.end_int - cr.start_int) ASC LIMIT 1) AS cloud_class,
                       (SELECT ir.risk_score FROM ip_risk ir WHERE base.n BETWEEN ir.start_int AND ir.end_int
                          ORDER BY ir.risk_score DESC LIMIT 1) AS ip_risk_score,
                       (SELECT ir.risk_reason FROM ip_risk ir WHERE base.n BETWEEN ir.start_int AND ir.end_int
                          ORDER BY ir.risk_score DESC LIMIT 1) AS ip_risk_reason
                FROM base WHERE rn = 1
                """
            ).fetch_arrow_table()  # materialize NOW: a lazy reader would stream after unregister("q")
        finally:
            con.unregister("q")

    def do_put(self, context, descriptor, reader, writer):
        dataset_name = descriptor.path[0].decode("utf-8")
        table = reader.read_all()
        if table.num_rows == 0:
            return

        # --- CUSTOM CERTSTREAM BGP ROUTING ---
        if dataset_name in ["brand_hits", "platform_hits", "burst_anomalies", "new_domains", "signals", "hourly_threat"]:
            import time
            import uuid
            import os
            import json
            import pyarrow.parquet as pq
            
            batch_id = f"{int(time.time())}_{uuid.uuid4().hex[:6]}"
            
            # --- 1. FIRE FULLY RESOLVED ALERTS DIRECTLY TO REDIS ---
            if dataset_name in ["brand_hits", "platform_hits"]:
                try:
                    import redis
                    r = redis.Redis(host='10.0.0.2', port=6379, db=0,
                                    password=os.getenv("REDIS_PASSWORD", "datazag"))
                    
                    def _as_list(v):
                        # The producer may send these as native Arrow list<string>
                        # columns (→ Python list) or as JSON strings. Accept either.
                        if v is None:
                            return []
                        if isinstance(v, list):
                            return v
                        if isinstance(v, (str, bytes, bytearray)):
                            if not v:
                                return []
                            try:
                                return json.loads(v)
                            except (ValueError, TypeError):
                                return []
                        return []

                    for row in table.to_pylist():
                        inc_id = f"INC-{int(time.time())}-{uuid.uuid4().hex[:6]}"
                        domain = row.get("domain", "")
                        root = row.get("root", "")

                        a_records = _as_list(row.get("a_records"))
                        ns_records = _as_list(row.get("ns_records"))
                        mx_records = _as_list(row.get("mx_records"))
                        triggers = _as_list(row.get("triggers"))

                        # Rich Go-side verdicts the resolver + dispatcher already
                        # carry as columns. Previously dropped here, which left every
                        # alert with no reason codes and confidence 0 — so the
                        # corroboration-escalation path and the INFO tier were dead
                        # code, and orange alerts rendered "_No annotations_" with a
                        # 0.00 score. Carry them through.
                        alert_reasons = _as_list(row.get("alert_reasons"))
                        confidence_score = int(row.get("confidence_score") or 0)
                        # Backend IPs the resolver drilled for NS/MX hosts — exposed
                        # under the NS_A/MX_A shape brand_orchestrator scores, so
                        # nameserver/mail infra is scored, not just the web A records.
                        ns_ips = _as_list(row.get("ns_ips"))
                        mx_ips = _as_list(row.get("mx_ips"))

                        # Calculate E2E Latency for SLA Tracking (Target < 5 seconds)
                        capture_ts = row.get("capture_timestamp")
                        e2e_latency = round(time.time() - capture_ts, 3) if capture_ts else -1

                        # A brand/platform word on a SUBDOMAIN label (domain != root) is a
                        # much weaker signal than a match on the registrable domain itself:
                        # facebook.figura.com / coach.smartmarketvendor.com are usually
                        # benign third-party subdomains, not impersonations. Deceptive
                        # subdomains do exist (zoom.us.evil.id), so don't drop them — flag
                        # them and downgrade brand subdomain hits CRITICAL→HIGH so
                        # brand_orchestrator can require corroboration (gold infra risk)
                        # before paging a customer, instead of CRITICAL on every subdomain.
                        is_subdomain = bool(root) and domain != root
                        if dataset_name == "brand_hits":
                            severity = "HIGH" if is_subdomain else "CRITICAL"
                        else:
                            severity = "HIGH"

                        alert_data = {
                            "incident_id": inc_id,
                            "domain": domain,
                            "root": root,
                            "triggers": triggers,
                            "severity": severity,
                            "subdomain_match": is_subdomain,
                            "confidence_score": confidence_score,
                            "alert_reasons": alert_reasons,
                            "dns": {
                                "A": a_records,
                                "NS": ns_records,
                                "MX": mx_records,
                                "NS_A": {"_resolved": ns_ips} if ns_ips else {},
                                "MX_A": {"_resolved": mx_ips} if mx_ips else {},
                            },
                            "e2e_latency_sec": e2e_latency,
                            "resolution_latency_ms": -1
                        }
                        r.lpush("queue:master_alerts_resolved", json.dumps(alert_data))
                        
                except Exception as e:
                    log.error(f"Failed to push fully resolved alert to Redis: {e}")

            # --- 2. FILTER ROOT DOMAINS VS SUBDOMAINS ---
            if dataset_name in ["brand_hits", "platform_hits"]:
                import pyarrow.compute as pc
                root_mask = pc.equal(table.column("domain"), table.column("root"))
                root_table = table.filter(root_mask)
                sub_table = table.filter(pc.invert(root_mask))
                
                if sub_table.num_rows > 0:
                    # Hit-subdomains (a brand/platform match on a subdomain, not the
                    # registered root) are captured as their OWN trend dataset —
                    # "{dataset}_subdomains" — with the SAME rich schema as the root
                    # hits, so impersonation trends include subdomains and root-vs-
                    # subdomain overlap is directly queryable, split for easy pruning.
                    # The compactor maps "{dataset}_subdomains" -> security-signals/
                    # raw_ingest alongside the root hits. The subdomain CORPUS is fed
                    # independently by the dispatcher's `subdomains` stream (main.go
                    # subdomainChan), so these are still in the corpus too.
                    sub_out = f"/root/staging/certstream/{dataset_name}_subdomains_{batch_id}.parquet"
                    os.makedirs(os.path.dirname(sub_out), exist_ok=True)
                    pq.write_table(sub_table, sub_out)

                table = root_table
                
            if table.num_rows == 0:
                return
            
            # 3. Slice Single Target Column for Celery DNS Resolvers
            try:
                if dataset_name == "new_domains":
                    import pyarrow.compute as pc
                    import pyarrow as pa
                    # Extract unique root domains so Celery only processes the registered domain.
                    # Older dispatchers omit the `root` column — fall back to `domain` so the
                    # batch is still routed for DNS resolution instead of being dropped.
                    root_col = 'root' if 'root' in table.column_names else 'domain'
                    if root_col == 'domain':
                        try:
                            sender = context.peer()
                        except Exception:
                            sender = "unknown"
                        log.warning(
                            f"[{dataset_name}] payload missing 'root' column; falling back to 'domain' "
                            f"| sender={sender} columns={table.column_names} rows={table.num_rows}"
                        )
                    unique_roots = pc.unique(table.column(root_col))
                    
                    # Pad with empty strings for standard Celery queue which requires full core DNS columns
                    empty_str_array = pa.array([""] * len(unique_roots), type=pa.string())
                    domain_only = pa.Table.from_arrays(
                        [unique_roots, empty_str_array, empty_str_array, empty_str_array], 
                        names=['domain', 'ns', 'ip', 'country_dm']
                    )
                else:
                    domain_only = table.select(['domain'])
            except KeyError:
                try:
                    sender = context.peer()
                except Exception:
                    sender = "unknown"
                log.error(
                    f"Missing required columns in PyArrow payload for {dataset_name}. "
                    f"Got columns={table.column_names} from sender={sender}. Skipping intercept."
                )
                return
            
            # 4. Target Dynamic Directory Map Mapping
            if dataset_name in ["brand_hits", "platform_hits"]:
                # Root domains get dropped to the STANDARD queue for daily tracking!
                dns_path = f"/srv/nfs/shared/subfiles/standard/{dataset_name}_{batch_id}.parquet"
                metadata_path = f"/root/staging/certstream/{dataset_name}_{batch_id}.parquet"
            elif dataset_name == "burst_anomalies":
                dns_path = f"/srv/nfs/shared/subfiles/priority/burst_anomalies_{batch_id}.parquet"
                metadata_path = f"/root/staging/certstream/burst_anomalies_{batch_id}.parquet"
            elif dataset_name == "new_domains":
                # Routed to standard queue for full DNS resolution identical to zone files
                dns_path = f"/srv/nfs/shared/subfiles/standard/new_domains_{batch_id}.parquet"
                metadata_path = f"/root/staging/certstream/new_domains_{batch_id}.parquet"
            elif dataset_name == "signals":
                # Explicitly bypass Celery DNS queues for signals!
                dns_path = None
                metadata_path = f"/root/signal_data/signals_{batch_id}.parquet"
            elif dataset_name == "hourly_threat":
                # Two kinds of batch arrive under this dataset name: the slim
                # 7-column dispatch from riskscore's hourly feed pipeline (needs
                # DNS resolution), and the rich resolved table coming back from
                # the Celery batch processor (has status/records_json columns).
                # Resolved batches must NOT be re-queued for DNS — that created
                # an endless resolve loop — and they go to a read-back mailbox
                # OUTSIDE the r2_compactor watch dirs, because the compactor
                # drains /root/staging within ~2 minutes, which starved the
                # fetch_hourly_threat_resolved poll loop.
                is_resolved = "status" in table.column_names or "records_json" in table.column_names
                if is_resolved:
                    dns_path = None
                    mailbox_dir = "/root/hourly_threat_resolved"
                    os.makedirs(mailbox_dir, exist_ok=True)
                    pq.write_table(table, f"{mailbox_dir}/hourly_threat_{batch_id}.parquet")
                    # Retain ~6h of resolved batches so the hourly poll always
                    # finds its run, then prune.
                    cutoff = time.time() - 6 * 3600
                    for old in Path(mailbox_dir).glob("*.parquet"):
                        try:
                            if old.stat().st_mtime < cutoff:
                                old.unlink()
                        except OSError:
                            pass
                else:
                    dns_path = f"/srv/nfs/shared/subfiles/priority/hourly_threat_{batch_id}.parquet"
                metadata_path = f"/root/staging/certstream/hourly_threat_{batch_id}.parquet"
                
            # 5. Synchronous NFS / Direct Disk Writes
            if dns_path:
                os.makedirs(os.path.dirname(dns_path), exist_ok=True)
                pq.write_table(domain_only, dns_path)
            
            os.makedirs(os.path.dirname(metadata_path), exist_ok=True)
            pq.write_table(table, metadata_path)

            # Corpus feed: new_domains get a second copy in a dedicated tree OUTSIDE
            # the r2_compactor watch dirs (/root/corpus/...), so new_domain_rollup.py
            # can roll them up hourly into the corpus the edge LMDB sync reads, without
            # racing the compactor (which drains /root/staging and would upload+delete
            # these first). The compactor still archives the metadata_path copy to R2.
            if dataset_name == "new_domains":
                try:
                    corpus_raw_dir = "/root/corpus/new_domains_raw"
                    os.makedirs(corpus_raw_dir, exist_ok=True)
                    pq.write_table(table, f"{corpus_raw_dir}/new_domains_{batch_id}.parquet")
                except Exception as e:
                    log.warning(f"Could not write new_domains corpus copy: {e}")

            # NOTE: this previously maintained an in-memory DuckDB "{dataset}_raw"
            # table (CREATE TABLE + INSERT per batch). That table was write-only —
            # nothing in the codebase ever queried it — and was never truncated, so
            # it grew unbounded (~11GB over ~17h) and pushed the host into swap. The
            # batch is already durably persisted as parquet above (metadata_path +
            # dns_path); the DuckLake catalog is populated downstream from those
            # files, not from this connection. Removed to stop the memory leak.

            log.info(f"[{dataset_name}] 💾 Explicit certstream Batch {batch_id} directly dispatched to NFS.")
            return

        # It natively routes our incoming certstream packets!
        if dataset_name in REALTIME_DATASETS:
            self._get_realtime_buffer(dataset_name).push(table.to_batches()[0])
        else:
            accumulator = self._get_accumulator(dataset_name)
            for batch in table.to_batches():
                accumulator.push(batch)

    # --- ADDED: Support for Bloom Sync Server reverse-requests ---
    def get_flight_info(self, context, descriptor):
        if descriptor.descriptor_type == flight.DescriptorType.CMD:
            payload = json.loads(descriptor.command.decode('utf-8'))
            
            if payload.get("target") == "incremental_new_domains":
                since_ts = payload.get("since_ts", 0.0)
                schema = pa.schema([('domain', pa.string())])
                ticket_data = json.dumps({"action": "fetch_incremental", "since_ts": since_ts}).encode('utf-8')
                endpoints = [flight.FlightEndpoint(ticket_data, [context.peer()])]
                return flight.FlightInfo(schema, descriptor, endpoints, -1, -1)
                
            elif payload.get("target") == "full_refresh_domains":
                schema = pa.schema([('domain', pa.string())])
                ticket_data = json.dumps({"action": "fetch_full"}).encode('utf-8')
                endpoints = [flight.FlightEndpoint(ticket_data, [context.peer()])]
                return flight.FlightInfo(schema, descriptor, endpoints, -1, -1)

            elif payload.get("target") in ["fetch_brands", "fetch_keywords", "fetch_platforms", "fetch_brand_dns_profiles", "fetch_gold_risk_asn", "fetch_gold_risk_prefix", "fetch_parked_indicators", "fetch_hourly_threat_resolved"]:
                if payload["target"] == "fetch_brand_dns_profiles":
                    schema = pa.schema([
                        ('brand', pa.string()), 
                        ('ip', pa.string()), 
                        ('asn', pa.int64()), 
                        ('prefix', pa.string()), 
                        ('ns', pa.string()), 
                        ('mx', pa.string())
                    ])
                elif payload["target"] == "fetch_parked_indicators":
                    schema = pa.schema([
                        ('indicator_type', pa.string()),
                        ('match_type', pa.string()),
                        ('pattern', pa.string()),
                        ('risk_bias', pa.int64()),
                        ('mapping_confidence', pa.int64()),
                        ('source', pa.string()),
                        ('notes', pa.string()),
                        ('updated_at', pa.timestamp('ms'))
                    ])
                elif payload["target"] == "fetch_gold_risk_asn":
                    schema = pa.schema([('asn', pa.int64()), ('infra_score', pa.float64()), ('abuse_score', pa.float64()), ('ip_pointer_penalty', pa.float64()), ('core_risk', pa.float64()), ('reason_codes', pa.string())])
                elif payload["target"] == "fetch_gold_risk_prefix":
                    schema = pa.schema([('prefix', pa.string()), ('asn', pa.int64()), ('infra_score', pa.float64()), ('reason_codes', pa.string())])
                elif payload["target"] == "fetch_brands":
                    schema = pa.schema([('brand', pa.string())])
                elif payload["target"] == "fetch_platforms":
                    schema = pa.schema([('platform', pa.string())])
                elif payload["target"] == "fetch_hourly_threat_resolved":
                    schema = pa.schema([
                        ('domain', pa.string()), ('a', pa.string()), ('ns', pa.string()), 
                        ('ip', pa.string()), ('country_dm', pa.string()), ('asn', pa.int64()), 
                        ('registrar', pa.string()), ('created_dt', pa.string())
                    ])
                else:
                    schema = pa.schema([('keyword', pa.string())])
                    
                ticket_data = json.dumps({"action": payload["target"]}).encode('utf-8')
                endpoints = [flight.FlightEndpoint(ticket_data, [context.peer()])]
                return flight.FlightInfo(schema, descriptor, endpoints, -1, -1)

        raise NotImplementedError("Unknown flight info request")

    def do_get(self, context, ticket):
        try:
            req = json.loads(ticket.ticket.decode("utf-8"))
            log.info(f"do_get request: {req}")

            if req.get("action") == "lookup_ips":
                ips = req.get("ips") or []
                table = self._lookup_ips(ips)
                log.info(f"🗺️  lookup_ips: {len(ips)} in -> {table.num_rows} matched")
                return flight.RecordBatchStream(table)

            if req.get("action") == "fetch_incremental":
                since_ts = float(req.get("since_ts", 0.0))
                log.info(f"📤 Edge node requesting domain diff since timestamp: {since_ts}")

                clauses = []

                # NOTE: uniques/domain/latest.parquet (the full-corpus baseline) is a
                # deduplicated, domain-only list with NO timestamp column, so it can never
                # contribute to an incremental diff — it is used only by fetch_full. The
                # incremental sources are the timestamped certstream + zone-delta files
                # below. (If corpus-level incremental is ever needed, add a `ts` column to
                # latest.parquet at generation time — see decision in target-architecture.)

                certstream_files = list(Path("/root/corpus/new_domains_compacted").glob("hourly_*.parquet"))
                if certstream_files:
                    clauses.append(f"""
                        SELECT domain
                        FROM read_parquet('/root/corpus/new_domains_compacted/hourly_*.parquet', union_by_name=True)
                        WHERE capture_timestamp > {since_ts}
                        AND domain IS NOT NULL AND domain != ''
                    """)

                delta_files = list(Path("/root/staging/zone_deltas").glob("????????.parquet"))
                if delta_files:
                    clauses.append(f"""
                        SELECT domain
                        FROM read_parquet('/root/staging/zone_deltas/*.parquet')
                        WHERE capture_timestamp > {since_ts}
                        AND domain IS NOT NULL AND domain != ''
                    """)

                if not clauses:
                    log.warning("No domain sources available for incremental sync.")
                    empty = pa.table({"domain": pa.array([], type=pa.string())})
                    return flight.RecordBatchStream(empty)

                union_sql = " UNION ALL ".join(clauses)

                # DISTINCT is okay for incremental if the result is small.
                arrow_table = self.conn.execute(f"""
                    SELECT DISTINCT domain
                    FROM ({union_sql})
                    WHERE domain IS NOT NULL AND domain != ''
                """).arrow()

                log.info(f"📤 Incremental: {arrow_table.num_rows:,} domains since {since_ts:.0f}")
                return flight.RecordBatchStream(arrow_table)

            elif req.get("action") == "fetch_full":
                log.info("📤 Edge node requesting FULL domain refresh. Streaming without DISTINCT.")

                clauses = ["""
                    SELECT domain
                    FROM 's3://domains-monitor/uniques/domain/latest.parquet'
                    WHERE domain IS NOT NULL AND domain != ''
                """]

                certstream_files = list(Path("/root/corpus/new_domains_compacted").glob("hourly_*.parquet"))
                if certstream_files:
                    clauses.append("""
                        SELECT domain
                        FROM read_parquet('/root/corpus/new_domains_compacted/hourly_*.parquet', union_by_name=True)
                        WHERE domain IS NOT NULL AND domain != ''
                    """)

                delta_files = list(Path("/root/staging/zone_deltas").glob("????????.parquet"))
                if delta_files:
                    clauses.append("""
                        SELECT domain
                        FROM read_parquet('/root/staging/zone_deltas/*.parquet')
                        WHERE domain IS NOT NULL AND domain != ''
                    """)

                union_sql = " UNION ALL ".join(clauses)

                cursor = self.conn.cursor()
                cursor.execute(f"""
                    SELECT domain
                    FROM ({union_sql})
                    WHERE domain IS NOT NULL AND domain != ''
                """)

                reader = cursor.fetch_record_batch(rows_per_batch=100_000)

                log.info(
                    "📤 Full refresh streaming started"
                    f"{' + certstream' if certstream_files else ''}"
                    f"{' + zone deltas' if delta_files else ''}"
                )

                return flight.RecordBatchStream(reader)

            elif req.get("action") == "fetch_brands":
                log.info("📤 Edge node requesting targeted brands list.")
                arrow_table = self.conn.execute("""
                    SELECT DISTINCT brand
                    FROM '/root/dnsall/brands.csv'
                """).arrow()
                return flight.RecordBatchStream(arrow_table)

            elif req.get("action") == "fetch_keywords":
                log.info("📤 Edge node requesting high risk keywords list.")
                arrow_table = self.conn.execute("""
                    SELECT DISTINCT keyword, CAST("Weight (1-10)" AS INTEGER) as weight
                    FROM '/root/dnsall/keywords.csv'
                """).arrow()
                return flight.RecordBatchStream(arrow_table)

            elif req.get("action") == "fetch_platforms":
                log.info("📤 Edge node requesting platforms list.")
                arrow_table = self.conn.execute("""
                    SELECT DISTINCT platform, category
                    FROM '/root/dnsall/platforms.csv'
                """).arrow()
                return flight.RecordBatchStream(arrow_table)

            elif req.get("action") == "fetch_brand_dns_profiles":
                log.info("📤 Edge node requesting Brand DNS Profiles.")
                try:
                    arrow_table = self.conn.execute("SELECT * FROM '/root/dnsall/brand_dns_profiles.parquet'").arrow()
                except Exception as e:
                    log.warning(f"Failed to fetch brand DNS profiles (file missing?): {e}")
                    # Provide minimal schema fallback
                    arrow_table = pa.table({
                        'brand': pa.array([], type=pa.string()), 
                        'ip': pa.array([], type=pa.string()),
                        'ns': pa.array([], type=pa.string()),
                        'mx': pa.array([], type=pa.string())
                    })
                return flight.RecordBatchStream(arrow_table)

            elif req.get("action") == "fetch_parked_indicators":
                log.info("📤 Edge node requesting Parked Indicators Parquet.")
                try:
                    arrow_table = self.conn.execute("SELECT indicator_type, match_type, pattern, risk_bias, mapping_confidence, source, notes, updated_at FROM '/root/dnsall/parked_indicators.parquet'").arrow()
                except Exception as e:
                    log.warning(f"Failed to fetch Parked Indicators (file missing?): {e}")
                    arrow_table = pa.table({
                        'indicator_type': pa.array([], type=pa.string()),
                        'match_type': pa.array([], type=pa.string()),
                        'pattern': pa.array([], type=pa.string()),
                        'risk_bias': pa.array([], type=pa.int64()),
                        'mapping_confidence': pa.array([], type=pa.int64()),
                        'source': pa.array([], type=pa.string()),
                        'notes': pa.array([], type=pa.string()),
                        'updated_at': pa.array([], type=pa.timestamp('ms'))
                    })
                return flight.RecordBatchStream(arrow_table)

            elif req.get("action") == "fetch_gold_risk_asn":
                log.info("📤 Edge node requesting Gold Risk ASN Parquet.")
                try:
                    arrow_table = self.conn.execute("SELECT * FROM '/root/dnsall/gold_risk_asn_latest.parquet'").arrow()
                except Exception as e:
                    log.warning(f"Failed to fetch Gold Risk ASN (file missing?): {e}")
                    arrow_table = pa.table({'asn': pa.array([], type=pa.int64()), 'infra_score': pa.array([], type=pa.float64()), 'abuse_score': pa.array([], type=pa.float64()), 'ip_pointer_penalty': pa.array([], type=pa.float64()), 'core_risk': pa.array([], type=pa.float64()), 'reason_codes': pa.array([], type=pa.string())})
                return flight.RecordBatchStream(arrow_table)

            elif req.get("action") == "fetch_gold_risk_prefix":
                log.info("📤 Edge node requesting Gold Risk Prefix Parquet.")
                try:
                    arrow_table = self.conn.execute("SELECT * FROM '/root/dnsall/gold_risk_prefix_latest.parquet'").arrow()
                except Exception as e:
                    log.warning(f"Failed to fetch Gold Risk Prefix (file missing?): {e}")
                    arrow_table = pa.table({'prefix': pa.array([], type=pa.string()), 'asn': pa.array([], type=pa.int64()), 'infra_score': pa.array([], type=pa.float64()), 'reason_codes': pa.array([], type=pa.string())})
                return flight.RecordBatchStream(arrow_table)

            elif req.get("action") == "fetch_hourly_threat_resolved":
                log.info("📤 Edge node requesting resolved hourly threats.")
                try:
                    # Served from the do_put mailbox (/root/hourly_threat_resolved),
                    # not /root/staging — the r2_compactor drains staging within
                    # ~2 minutes, so resolved batches never survived there long
                    # enough for the riskscore poll loop to find them.
                    arrow_table = self.conn.execute("""
                        SELECT domain, a, ns, ip, country_dm,
                               TRY_CAST(asn AS BIGINT) AS asn, registrar, created_dt
                        FROM read_parquet('/root/hourly_threat_resolved/*.parquet', union_by_name=True)
                    """).arrow()
                except Exception as e:
                    log.warning(f"Failed to fetch hourly_threat (file missing?): {e}")
                    arrow_table = pa.table({
                        'domain': pa.array([], type=pa.string()), 'a': pa.array([], type=pa.string()),
                        'ns': pa.array([], type=pa.string()), 'ip': pa.array([], type=pa.string()),
                        'country_dm': pa.array([], type=pa.string()), 'asn': pa.array([], type=pa.int64()),
                        'registrar': pa.array([], type=pa.string()), 'created_dt': pa.array([], type=pa.string())
                    })
                return flight.RecordBatchStream(arrow_table)

            raise NotImplementedError(f"Unknown ticket request: {req}")

        except Exception:
            log.exception("do_get failed")
            raise

    def _start_watchdog(self):
        def watch():
            while True:
                time.sleep(30)
                with self._accumulator_lock:
                    accumulators = list(self._accumulators.values())
                for acc in accumulators:
                    acc.flush_if_stale()
        threading.Thread(target=watch, daemon=True).start()
        log.info("🐕 Watchdog started (30s check interval)")

if __name__ == "__main__":
    server_location = "grpc://0.0.0.0:8815"
    server = GraphIngestServer(
        location=server_location,
        staging_dir="/root/staging",
    )
    log.info(f"🚀 Flight server listening at {server_location}")
    server.serve()

