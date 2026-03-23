import duckdb
import pyarrow as pa
import pyarrow.flight as flight
import threading
import time
import os
from datetime import datetime

class GraphIngestServer(flight.FlightServerBase):
    def __init__(self, location, db_path="master_graph.duckdb"):
        super().__init__(location)
        self.db_path = db_path

        # Connect to the native DuckDB file.
        # DuckDB handles its own WAL (Write-Ahead Log) for concurrent safety,
        # but we use a lightweight lock to prevent thread collision on massive bursts.
        self.conn = duckdb.connect(self.db_path)
        
        # Initialize tables if they don't exist
        self._init_schema()
        
        self.lock = threading.Lock()
        
        # Start the Silver Offload background thread
        self.silver_dir = "/root/celery_master/silver_ducklake"
        self.offload_interval = 60 # Wake up every 60 seconds to check thresholds
        self.last_export_ts = {} # Tracks the last export time per dataset
        self.flush_thread = threading.Thread(target=self._silver_offload_loop, daemon=True)
        self.flush_thread.start()

        print(f"✅ Connected to Master Graph Database: {self.db_path}")

    def _init_schema(self):
        # Create tables to ensure ON CONFLICT logic works immediately
        # (Assuming you have a schema defined externally, but adding safe IF NOT EXISTS creates based on our data)
        # Note: You likely have a dedicated schema migration script, so this is just a fallback for local testing.
        pass

    def do_put(self, context, descriptor, reader, writer):
        """
        Catches the Arrow Flight stream from the Celery workers.
        The 'descriptor' tells us which table this data belongs to.
        """
        # 1. Identify the incoming dataset (e.g., b'entity_domain')
        dataset_name = descriptor.path[0].decode('utf-8')

        # 2. Read the zero-copy Arrow Table from the network
        arrow_table = reader.read_all()
        num_rows = arrow_table.num_rows

        if num_rows == 0:
            return

        start_time = time.time()

        # 3. Route to the correct DuckDB UPSERT logic
        with self.lock:
            try:
                # DuckDB requires the variable to literally be in locals/globals,
                # but it can resolve it from the caller frame. 
                # It's safest to execute using locals bound explicitly if inside a function, 
                # but duckdb.execute uses inspection to find 'arrow_table'.
                self._route_and_upsert(dataset_name, arrow_table)
                elapsed = time.time() - start_time
                print(f"📥 [{dataset_name}] UPSERTED {num_rows} rows in {elapsed:.3f}s")
            except Exception as e:
                print(f"❌ ERROR inserting into {dataset_name}: {e}")

    def _route_and_upsert(self, dataset_name: str, arrow_table: pa.Table):
        """
        DuckDB's superpower: It can query the Python variable 'arrow_table'
        directly from RAM without any serialization or conversion!
        """
        # Auto-create the table if it does not exist using the Arrow schema
        self.conn.execute(f"CREATE TABLE IF NOT EXISTS {dataset_name} AS SELECT * FROM arrow_table LIMIT 0")
        
        # Need to ensure unique indexes exist for ON CONFLICT to work
        self._ensure_indexes(dataset_name)

        if dataset_name in ["dns_results", "dns_expanded"]:
            # Dynamically build the ON CONFLICT query to handle schema evolution
            columns = arrow_table.column_names
            updates = ",\n                    ".join(f"{col} = EXCLUDED.{col}" for col in columns if col != "domain")
            
            self.conn.execute(f"""
                INSERT INTO {dataset_name}
                SELECT * FROM arrow_table
                ON CONFLICT (domain) DO UPDATE SET
                    {updates};
            """)

        elif dataset_name == "entity_domain":
            self.conn.execute("""
                INSERT INTO entity_domain
                SELECT * FROM arrow_table
                ON CONFLICT (domain_id) DO UPDATE SET
                    last_seen_ts = EXCLUDED.last_seen_ts,
                    source_flags = EXCLUDED.source_flags;
            """)

        elif dataset_name == "entity_ip":
            self.conn.execute("""
                INSERT INTO entity_ip
                SELECT * FROM arrow_table
                ON CONFLICT (ip_id) DO UPDATE SET
                    last_seen_ts = EXCLUDED.last_seen_ts;
            """)

        elif dataset_name == "entity_edge":
            self.conn.execute("""
                INSERT INTO entity_edge
                SELECT * FROM arrow_table
                ON CONFLICT (src_type, src_id, dst_type, dst_id, edge_type)
                DO UPDATE SET
                    last_seen_ts = EXCLUDED.last_seen_ts,
                    last_observed_ts = EXCLUDED.last_observed_ts,
                    attrs = EXCLUDED.attrs;
            """)

        elif dataset_name == "signal_observation":
            # Observations are an append-only ledger of evidence
            self.conn.execute("""
                INSERT INTO signal_observation
                SELECT * FROM arrow_table
                -- Assuming obs_id is the primary key for deduplication
                ON CONFLICT (obs_id) DO NOTHING;
            """)

        elif dataset_name == "risk_score":
            self.conn.execute("""
                INSERT INTO risk_score
                SELECT * FROM arrow_table
                ON CONFLICT (entity_type, entity_id) DO UPDATE SET
                    score = EXCLUDED.score,
                    label = EXCLUDED.label,
                    top_reason_code = EXCLUDED.top_reason_code,
                    updated_ts = EXCLUDED.updated_ts;
            """)

        elif dataset_name == "risk_factor":
            # Append-only context for why a score was generated
            self.conn.execute("""
                INSERT INTO risk_factor
                SELECT * FROM arrow_table;
            """)

        elif dataset_name == "entity_cert":
            self.conn.execute("""
                INSERT INTO entity_cert
                SELECT * FROM arrow_table
                ON CONFLICT (cert_id) DO NOTHING;
            """)

        elif dataset_name == "entity_subdomain":
            self.conn.execute("""
                INSERT INTO entity_subdomain
                SELECT * FROM arrow_table
                ON CONFLICT (subdomain_id) DO UPDATE SET
                    last_seen_ts = EXCLUDED.last_seen_ts;
            """)
        else:
            print(f"⚠️ Warning: Unknown dataset name '{dataset_name}' received.")

    def _ensure_indexes(self, dataset_name: str):
        """Create primary key constraints dynamically if they don't exist yet so ON CONFLICT works."""
        
        # In DuckDB, to add a constraint after table creation, we often create a UNIQUE INDEX.
        # ON CONFLICT works with unique indexes.
        
        indexes = {
            "dns_results": "CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_results_domain ON dns_results(domain);",
            "dns_expanded": "CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_expanded_domain ON dns_expanded(domain);",
            "entity_domain": "CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_domain_id ON entity_domain(domain_id);",
            "entity_ip": "CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_ip_id ON entity_ip(ip_id);",
            "entity_edge": "CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_edge_pk ON entity_edge(src_type, src_id, dst_type, dst_id, edge_type);",
            "signal_observation": "CREATE UNIQUE INDEX IF NOT EXISTS idx_sig_obs_id ON signal_observation(obs_id);",
            "risk_score": "CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_score_pk ON risk_score(entity_type, entity_id);",
            "entity_cert": "CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_cert_id ON entity_cert(cert_id);",
            "entity_subdomain": "CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_subdomain_id ON entity_subdomain(subdomain_id);"
        }
        
        if dataset_name in indexes:
            try:
                self.conn.execute(indexes[dataset_name])
            except Exception as e:
                # Might already exist or table structure differs, ignore safely
                pass

    def _silver_offload_loop(self):
        """
        Background daemon that wakes up periodically, grabs all data from the DuckDB buffer,
        exports it as pristine Parquet files to the Silver Ducklake, and deletes the buffered rows.
        """
        # Define specific flush profiles per dataset: (row_threshold, max_age_seconds)
        # Express datasets (IPs, edges, signals) flush fast. Bulk datasets wait longer.
        # Ensure row counts match your preferred batch sizing!
        dataset_profiles = {
            "dns_results": (100000, 3600),        # High volume: 100k rows or 1 hour
            "dns_expanded": (100000, 3600),       
            "entity_domain": (100000, 3600),      
            "entity_ip": (5000, 300),             # Express: 5k rows or 5 mins
            "entity_edge": (5000, 300),           
            "signal_observation": (5000, 300),    
            "risk_score": (50000, 3600),          
            "risk_factor": (50000, 3600),         
            "entity_cert": (50000, 3600),         
            "entity_subdomain": (50000, 3600)     
        }

        # Initialize tracking on first run
        now_ts = time.time()
        for d in dataset_profiles.keys():
            if d not in self.last_export_ts:
                self.last_export_ts[d] = now_ts

        while True:
            time.sleep(self.offload_interval)
            
            with self.lock:
                now_ts = time.time()
                for dataset, (row_thresh, time_thresh) in dataset_profiles.items():
                    try:
                        # Check if table exists (in case no data has arrived yet)
                        res = self.conn.execute(f"SELECT count(*) FROM information_schema.tables WHERE table_name='{dataset}'").fetchone()
                        if res and res[0] > 0:
                            count = self.conn.execute(f"SELECT COUNT(*) FROM {dataset}").fetchone()[0]
                            elapsed_seconds = now_ts - self.last_export_ts[dataset]
                            
                            # Decide whether we need to flush this specific dataset
                            if count >= row_thresh or (count > 0 and elapsed_seconds >= time_thresh):
                                current_ts_str = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                                dataset_dir = os.path.join(self.silver_dir, dataset)
                                os.makedirs(dataset_dir, exist_ok=True)
                                parquet_path = os.path.join(dataset_dir, f"batch_{current_ts_str}.parquet")
                                
                                # Offload to perfectly compressed Parquet file
                                self.conn.execute(f"COPY (SELECT * FROM {dataset}) TO '{parquet_path}' (FORMAT PARQUET)")
                                
                                # Instantly wipe the buffer clean
                                self.conn.execute(f"DELETE FROM {dataset}")
                                
                                # Reset the export timer for this dataset
                                self.last_export_ts[dataset] = time.time()
                                
                                reason = "row threshold" if count >= row_thresh else "time limit"
                                print(f"🌊 [Silver] Exported {count} rows of {dataset} to {parquet_path} ({reason}).")
                    except Exception as e:
                        print(f"⚠️ [Silver Offload] Error exporting {dataset}: {e}")

if __name__ == '__main__':
    # Listen on all network interfaces on port 8815
    server_location = "grpc://0.0.0.0:8815"
    server = GraphIngestServer(server_location)

    print(f"🚀 Master Arrow Flight Server listening at {server_location}...")
    server.serve()
