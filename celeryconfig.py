# celeryconfig.py
import os

# ============================================================
# Broker + backend
# ============================================================

broker_url = os.getenv(
    "CELERY_BROKER_URL",
    "redis://:datazag@10.0.0.2:6379/0"
)

result_backend = os.getenv(
    "CELERY_RESULT_BACKEND",
    "redis://:datazag@10.0.0.2:6379/0"
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

# With a Redis broker + task_acks_late, an unacked message is redelivered
# to another worker after visibility_timeout (default 1h). Standard batches
# routinely run 25min+ and can approach the time limits, so the default
# caused duplicate processing. Must exceed the worst-case task duration.
# Keep in sync with the master's celeryconfig.py.
broker_transport_options = {"visibility_timeout": 43200}  # 12 hours

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
# Child recycling
# worker_max_tasks_per_child  — replace the pool child after N tasks.
#
# Without it the child lived until the worker restarted. On 2026-09-07
# a soft-time-limit signal left .62's child marked as running an event
# loop; every later task in that process failed in milliseconds, so it
# took most tasks off the shared queues for four days (119,371 failures,
# ~44M refresh lookups to failed/). loop_guard.py fixes that case; this
# caps ANY unknown poisoned-child state at N-1 bad tasks.
# 10 rather than 1: sub-second priority tasks would otherwise pay a fork
# each, and 9 instant failures is seconds of damage, not days.
# ============================================================

worker_max_tasks_per_child = int(os.getenv("CELERY_MAX_TASKS_PER_CHILD", "10"))

# ============================================================
# Monitoring — emit task events so Flower's task view shows the
# fleet's work (equivalent to starting workers with -E)
# ============================================================

worker_send_task_events = True
task_send_sent_event    = True

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
