"""
Lightweight reporter that slaves can use to submit DNS cache updates to the master
via a Celery task. The master should run the worker that registers the
'dns_cache.report_update' task.
"""
from typing import List

try:
    # Import the Celery app used across the project
    from celery_app import app
except Exception:
    app = None


def report_dns_update(rtype: str, name: str, rcode: str, answers: List[str], ttl: int) -> bool:
    """Send a write-back request to the master via Celery.

    Returns True if the task was enqueued, False otherwise.
    """
    if app is None:
        return False
    try:
        app.send_task("dns_cache.report_update", args=[rtype, name, rcode, answers or [], int(ttl or 0)])
        return True
    except Exception:
        return False

def report_ptr_update(reverse_name: str, rcode: str, answers: List[str], ttl: int) -> bool:
    """Send a PTR write-back request to the master via Celery."""
    if app is None:
        return False
    try:
        app.send_task("dns_cache.report_ptr_update", args=[reverse_name, rcode, answers or [], int(ttl or 0)])
        return True
    except Exception:
        return False
