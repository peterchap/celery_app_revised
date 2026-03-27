# celery_app.py (worker)
from __future__ import annotations

import os
from celery import Celery
from kombu import Exchange, Queue

BROKER_URL = os.getenv(
    "CELERY_BROKER_URL",
    "pyamqp://admin:1Francis2@10.0.0.2:5672//",
)

app = Celery("datazag", broker=BROKER_URL, include=["task"])
app.config_from_object('celeryconfig')

# ============================================================
# Exchanges
# ============================================================

priority_exchange   = Exchange("priority_exchange",   type="direct", durable=True)
new_domain_exchange = Exchange("new_domain_exchange", type="direct", durable=True)
retry_exchange      = Exchange("retry_exchange",      type="direct", durable=True)
standard_exchange   = Exchange("standard_exchange",   type="direct", durable=True)

# ============================================================
# Queues
# Priority order (highest → lowest):
#   priority_queue    — certstream phishing alerts, immediate
#   new_domain_queue  — first-seen domains, ahead of bulk refresh
#   retry_queue       — failed task re-attempts
#   standard_queue    — bulk domain refresh
# ============================================================

app.conf.task_queues = [
    Queue("priority_queue",   exchange=priority_exchange,   routing_key="priority_queue",   durable=True),
    Queue("new_domain_queue", exchange=new_domain_exchange, routing_key="new_domain_queue", durable=True),
    Queue("retry_queue",      exchange=retry_exchange,      routing_key="retry_queue",       durable=True),
    Queue("standard_queue",   exchange=standard_exchange,   routing_key="standard_queue",    durable=True),
]

# ============================================================
# Routing
# ============================================================

app.conf.task_routes = {
    "task.process_file_priority":   {"queue": "priority_queue",   "routing_key": "priority_queue"},
    "task.process_file_new_domain": {"queue": "new_domain_queue", "routing_key": "new_domain_queue"},
    "task.process_file_retry":      {"queue": "retry_queue",      "routing_key": "retry_queue"},
    "task.process_file":            {"queue": "standard_queue",   "routing_key": "standard_queue"},
}

app.conf.task_default_queue         = "standard_queue"
app.conf.task_default_exchange      = "standard_exchange"
app.conf.task_default_exchange_type = "direct"
app.conf.task_default_routing_key   = "standard_queue"
