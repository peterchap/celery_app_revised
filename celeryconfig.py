# celeryconfig.py
import os

# ============================================================
# Broker + backend
# ============================================================

broker_url = os.getenv(
    "CELERY_BROKER_URL",
    "pyamqp://admin:1Francis2@10.0.0.2:5672//"
)

result_backend = os.getenv(
    "CELERY_RESULT_BACKEND",
    "redis://10.0.0.2:6379/0"
)

# ============================================================
# Beat scheduler — redbeat prevents double-firing on restart
# Uses a Redis lock so only one beat instance runs at a time
# ============================================================

beat_scheduler        = "redbeat.schedulers:RedBeatScheduler"
redbeat_redis_url     = os.getenv("CELERY_RESULT_BACKEND", "redis://10.0.0.2:6379/0")
redbeat_lock_timeout  = 60   # seconds — beat must check in within this window
                              # or the lock is released for another instance

broker_heartbeat         = 10   # seconds — detect dead connections faster
broker_connection_timeout = 30  # don't wait too long on a lost broker

# Serialisation
# ============================================================

task_serializer   = "json"
result_serializer = "json"
accept_content    = ["json"]

# ============================================================
# Reliability
# task_acks_late              — only ack after the task completes,
#                               so a lost worker re-queues the task
# task_reject_on_worker_lost  — explicit reject (not ack) if worker
#                               dies mid-task, works with acks_late
# worker_prefetch_multiplier  — each worker holds exactly one task
#                               at a time; critical for your pipeline
#                               to prevent queue flooding
# ============================================================

task_acks_late             = True
task_reject_on_worker_lost = True
worker_prefetch_multiplier = 1

# ============================================================
# Results
# ============================================================

result_expires = 3600   # 1 hour — prevents Redis bloat

# ============================================================
# Time
# ============================================================

timezone   = "UTC"
enable_utc = True

# ============================================================
# Broker connection
# ============================================================

broker_connection_retry_on_startup = True
