from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from celery_app import app
from dns_module.dns_application import DNSApplication

# ============================================================
# Paths
# ============================================================

ROOT = Path("/mnt/shared")
IN_PROGRESS_FOLDER = ROOT / "inprogress"
PROCESSED_FOLDER = ROOT / "processed"
FAILED_FOLDER = ROOT / "failed"
LOG_DIR = ROOT / "logs"

for p in [IN_PROGRESS_FOLDER, PROCESSED_FOLDER, FAILED_FOLDER, LOG_DIR]:
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


async def run_dns_task(dns_app_instance: DNSApplication, file_key: str) -> None:
    # keep positional call to remain compatible with your existing DNSApplication
    await dns_app_instance.run_dns(file_key)


# ============================================================
# Celery task
# ============================================================

@app.task(name="task.process_file", acks_late=True, soft_time_limit=3600, time_limit=4200)
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
        dns_app_instance = DNSApplication(
            directory="/root/celery_project/",
            file_key=file,
            output_directory="/mnt/shared/results/",
        )

        asyncio.run(run_dns_task(dns_app_instance, file))

        if input_path.exists():
            processed_path = move_to_processed(input_path)

            payload = {
                "status": "success",
                "file": filename,
                "relative_path": file,
                "workload_class": workload_class,
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

    except Exception as e:
        log.exception("Task failed for file=%s error=%s", file, e)

        if input_path.exists():
            failed_path = move_to_failed(input_path)
            payload = {
                "status": "failed",
                "file": filename,
                "relative_path": file,
                "workload_class": workload_class,
                "error": str(e),
            }
            write_sidecar_json(failed_path, payload)
            log.error("Moved failed file to %s", failed_path)

        raise
