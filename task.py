from __future__ import annotations

import json
import logging
import os
import socket
import shutil
from pathlib import Path
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded

import cname_resolver
from celery_app import app
from dns_module.dns_application import DNSApplication
from loop_guard import run_coroutine

# ============================================================
# Paths
# ============================================================

ROOT = Path("/mnt/shared")
IN_PROGRESS_FOLDER = ROOT / "inprogress"
PROCESSED_FOLDER = ROOT / "processed"
FAILED_FOLDER = ROOT / "failed"
RETRY_FOLDER = ROOT / "retries"
LOG_DIR = ROOT / "logs"

for p in [IN_PROGRESS_FOLDER, PROCESSED_FOLDER, FAILED_FOLDER, RETRY_FOLDER, LOG_DIR]:
    p.mkdir(parents=True, exist_ok=True)

# ============================================================
# Logging
# ============================================================

LOG_FILE = LOG_DIR / "worker_task.log"

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s:%(message)s",
)
log = logging.getLogger(__name__)

# ============================================================
# Helpers
# ============================================================

def classify_filename(filename: str) -> str:
    name = filename.lower()
    if name.startswith("prio_"):
        return "priority"
    if name.startswith("new_"):
        return "new_domain"
    if name.startswith("retry_"):
        return "retry"
    if name.startswith("std_"):
        return "standard"
    return "unknown"


def write_sidecar_json(path: Path, payload: dict[str, Any]) -> None:
    sidecar = path.with_suffix(path.suffix + ".json")
    with sidecar.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True, default=str)


def move_to_processed(path: Path) -> Path:
    dst = PROCESSED_FOLDER / path.name
    shutil.move(str(path), str(dst))
    return dst


def move_to_failed(path: Path) -> Path:
    dst = FAILED_FOLDER / path.name
    shutil.move(str(path), str(dst))
    return dst


def move_to_retries(path: Path) -> Path:
    """Hand the file back to the master's retry sweep, which re-queues it
    with a retry_N_ prefix and moves it to failed/ after 4 attempts.
    No sidecar JSON here — the sweep enqueues every file in the folder,
    so a .json would itself be sent round the pipeline."""
    dst = RETRY_FOLDER / path.name
    shutil.move(str(path), str(dst))
    return dst


async def run_dns_task(dns_app_instance: DNSApplication, file_key: str) -> None:
    # keep positional call to remain compatible with your existing DNSApplication
    await dns_app_instance.run_dns(file_key)


# ============================================================
# Celery task
# ============================================================

# Limits must fit the worst-case batch (observed up to ~70min in production)
# and stay below the 12h broker visibility_timeout in celeryconfig.py.
@app.task(name="task.process_file", acks_late=True, soft_time_limit=7200, time_limit=7500)
def process_file(file: str) -> dict[str, Any]:
    """
    Expected file examples:
      inprogress/std_light_batch_000001.parquet
      inprogress/prio_new_batch_000002.parquet
      inprogress/retry_dns_1_std_light_batch_000001.parquet
    """
    filename = Path(file).name
    workload_class = classify_filename(filename)
    input_path = IN_PROGRESS_FOLDER / filename

    log.info("Starting task for file=%s workload=%s", file, workload_class)

    try:
        filename = Path(file).name
        dns_app_instance = DNSApplication(
            directory="/root/celery_app/",
            file_key=f"inprogress/{filename}",
            input_directory="/mnt/shared/",
            output_directory="/mnt/shared/results/",
        )
        # Not asyncio.run(): a soft-time-limit signal landing inside run_forever's setup
        # left .62 marked as running a loop, and every later task in that process failed
        # instantly (2026-09-07..09-11). See loop_guard.py.
        run_coroutine(lambda: run_dns_task(dns_app_instance, f"inprogress/{filename}"))

        if input_path.exists():
            processed_path = move_to_processed(input_path)

            payload = {
                "status": "success",
                "file": filename,
                "relative_path": file,
                "workload_class": workload_class,
                "worker": socket.gethostname(),
                "used_flight": bool(os.getenv("FLIGHT_SERVER_URL", "").strip()),
                "flight_server_url": os.getenv("FLIGHT_SERVER_URL", "").strip() or None,
            }
            write_sidecar_json(processed_path, payload)

            log.info("Task completed successfully for file=%s moved_to=%s", filename, processed_path)
            return payload

        msg = f"File {filename} not found in in-progress folder after processing"
        log.warning(msg)
        return {
            "status": "success_missing_input",
            "file": filename,
            "relative_path": file,
            "workload_class": workload_class,
            "message": msg,
        }

    except SoftTimeLimitExceeded:
        log.error("Task timed out for file=%s workload=%s", file, workload_class)
        if input_path.exists():
            retry_path = move_to_retries(input_path)
            log.error("Moved timed-out file to %s for re-queue", retry_path)
        raise

    except Exception as e:
        log.exception("Task failed for file=%s error=%s", file, e)

        if input_path.exists():
            retry_path = move_to_retries(input_path)
            log.error(
                "Moved failed file to %s for re-queue (workload=%s error=%s) — "
                "goes to failed/ after 4 attempts",
                retry_path, workload_class, e,
            )

        raise

@app.task(name="task.process_file_priority", acks_late=True, soft_time_limit=1800, time_limit=2400)
def process_file_priority(file: str) -> dict[str, Any]:
    """
    Certstream / phishing alert domains.
    Shorter time limits — these must complete fast.
    """
    return process_file(file)


@app.task(name="task.process_file_new_domain", acks_late=True, soft_time_limit=7200, time_limit=7500)
def process_file_new_domain(file: str) -> dict[str, Any]:
    """
    First-seen domains — same processing as standard
    but routed through new_domain_queue for prioritisation.
    """
    return process_file(file)


# ============================================================
# cname_queue: CNAME + A resolution of certstream subdomains, on a SEPARATE path.
# Design: datazag-pipeline/work/subdomain-cname-worker-path.md. It uses its own folders
# (cname_inprogress/, cname_done/, cname_failed/) and NEVER inprogress/ or retries/. The master's
# orphan reconciler and retry sweep re-enqueue anything in those folders onto retry_queue, i.e.
# into DNSApplication and the lake. Results go to Flight dataset cname_resolution, which the
# master lands outside DuckLake.
# ============================================================

CNAME_IN_PROGRESS_FOLDER = ROOT / "cname_inprogress"
CNAME_DONE_FOLDER = ROOT / "cname_done"
CNAME_FAILED_FOLDER = ROOT / "cname_failed"
CNAME_RESULTS_FOLDER = ROOT / "cname_results"   # fallback only; nothing ingests it
CNAME_QPS = float(os.getenv("CNAME_QPS", "40"))

for p in [CNAME_IN_PROGRESS_FOLDER, CNAME_DONE_FOLDER, CNAME_FAILED_FOLDER, CNAME_RESULTS_FOLDER]:
    p.mkdir(parents=True, exist_ok=True)


def _send_cname_results(table, filename: str) -> str:
    """Flight to the master, else a local parquet the operator re-sends. Returns where it went."""
    import pyarrow.parquet as pq

    url = os.getenv("FLIGHT_SERVER_URL", "").strip()
    if url:
        import pyarrow.flight as flight
        try:
            client = flight.FlightClient(url)
            try:
                writer, _ = client.do_put(flight.FlightDescriptor.for_path(cname_resolver.DATASET), table.schema)
                writer.write_table(table)
                writer.close()
            finally:
                client.close()
            return url
        except Exception as e:
            log.error("cname Flight send failed for %s: %s. Writing local parquet instead.", filename, e)
    out = CNAME_RESULTS_FOLDER / f"{Path(filename).stem}.parquet"
    pq.write_table(table, str(out))
    return str(out)


# 5,000 hosts at 40 qps is ~125 s; the limits leave room for retries and a slow resolver while
# keeping one file short enough that this queue never holds a worker for long.
@app.task(name="task.resolve_cnames", acks_late=True, soft_time_limit=900, time_limit=960)
def resolve_cnames(file: str) -> dict[str, Any]:
    filename = Path(file).name
    input_path = CNAME_IN_PROGRESS_FOLDER / filename
    log.info("Starting cname task for file=%s qps=%s", filename, CNAME_QPS)
    try:
        hosts = cname_resolver.read_hosts(input_path)
        rows = run_coroutine(lambda: cname_resolver.resolve_hosts(hosts, qps=CNAME_QPS))
        table = cname_resolver.to_table(rows, source_file=filename)
        sent_to = _send_cname_results(table, filename)
        shutil.move(str(input_path), str(CNAME_DONE_FOLDER / filename))
        payload = {"status": "success", "file": filename, "hosts": len(hosts),
                   "with_cname": sum(1 for r in rows if r["cnames"]),
                   "worker": socket.gethostname(), "sent_to": sent_to}
        log.info("cname task done: %s", payload)
        return payload
    except BaseException as e:
        # Includes SoftTimeLimitExceeded. Always cname_failed/, never retries/ (see above).
        log.exception("cname task failed for file=%s: %r", filename, e)
        if input_path.exists():
            shutil.move(str(input_path), str(CNAME_FAILED_FOLDER / filename))
        raise


@app.task(name="task.process_file_retry", acks_late=True, soft_time_limit=7200, time_limit=7500)
def process_file_retry(file: str) -> dict[str, Any]:
    """
    Previously failed files — same processing pipeline,
    retry routing handled by masterapp.
    """
    return process_file(file)