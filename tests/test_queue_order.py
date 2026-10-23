"""The broker must hand out work by queue order, not round robin (2026-10-23 incident).

Stdlib only: celeryconfig is a plain module of settings, so it is read directly.
"""
import celeryconfig


def test_queues_are_consumed_in_priority_order():
    assert celeryconfig.broker_transport_options["queue_order_strategy"] == "priority"


def test_visibility_timeout_still_exceeds_the_longest_task():
    # task.process_file hard limit is 7500s; the redelivery window must stay well above it.
    assert celeryconfig.broker_transport_options["visibility_timeout"] == 43200
