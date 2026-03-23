from __future__ import annotations

import os

from celery import Celery
from kombu import Exchange, Queue

# ============================================================
# Broker
# ============================================================

BROKER_URL = os.getenv(
    "CELERY_BROKER_URL",
    "pyamqp://admin:1Francis2@10.0.0.2:5672//",
)

app = Celery("celery_app", broker=BROKER_URL)

# ============================================================
# Queue definitions
# ============================================================

priority_exchange = Exchange("priority_exchange", type="direct", durable=True)
retry_exchange = Exchange("retry_exchange", type="direct", durable=True)
standard_exchange = Exchange("standard_exchange", type="direct", durable=True)

app.conf.update(
    broker_connection_retry_on_startup=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
)

app.conf.task_queues = [
    Queue(
        "priority_queue",
        exchange=priority_exchange,
        routing_key="priority_queue",
        durable=True,
    ),
    Queue(
        "retry_queue",
        exchange=retry_exchange,
        routing_key="retry_queue",
        durable=True,
    ),
    Queue(
        "standard_queue",
        exchange=standard_exchange,
        routing_key="standard_queue",
        durable=True,
    ),
]

app.conf.task_routes = {
    "task.process_file": {
        "queue": "standard_queue",
        "routing_key": "standard_queue",
    },
}

app.conf.task_default_queue = "standard_queue"
app.conf.task_default_exchange = "standard_exchange"
app.conf.task_default_exchange_type = "direct"
app.conf.task_default_routing_key = "standard_queue"
