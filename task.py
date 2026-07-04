from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import shutil
from pathlib import Path
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded

from celery_app import app
from dns_module.dns_application import DNSApplication

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
        asyncio.run(run_dns_task(dns_app_instance, f"inprogress/{filename}"))

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


@app.task(name="task.process_file_retry", acks_late=True, soft_time_limit=7200, time_limit=7500)
def process_file_retry(file: str) -> dict[str, Any]:
    """
    Previously failed files — same processing pipeline,
    retry routing handled by masterapp.
    """
    return process_file(file)