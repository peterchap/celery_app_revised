"""loop_guard.run_coroutine must survive the interrupt that poisoned resolver .62.

Stdlib only (no celery import): SoftTimeLimitExceeded is an ordinary Exception subclass
raised from a signal handler, so a local stand-in raised at the same point is faithful.
"""
from __future__ import annotations

import asyncio
from asyncio import base_events, events

import pytest

import loop_guard


class FakeSoftTimeLimit(Exception):
    """Stands in for billiard's SoftTimeLimitExceeded (also an Exception subclass)."""


@pytest.fixture(autouse=True)
def clean_thread_state():
    events._set_running_loop(None)
    yield
    events._set_running_loop(None)
    events.set_event_loop(None)


@pytest.fixture
def interrupt_after_running_mark(monkeypatch):
    """Raise once, immediately after run_forever's setup marks the thread as running a loop.

    That is the instant a signal can land before run_forever enters the try whose finally
    would clear the mark — the window that poisoned .62.
    """
    real_set = events._set_running_loop
    armed = {"on": True}

    def set_then_raise(loop):
        real_set(loop)
        if loop is not None and armed["on"]:
            armed["on"] = False
            raise FakeSoftTimeLimit()

    monkeypatch.setattr(base_events.events, "_set_running_loop", set_then_raise)
    return armed


async def _value(v):
    await asyncio.sleep(0)
    return v


def test_bare_asyncio_run_is_poisoned_by_the_interrupt(interrupt_after_running_mark, monkeypatch):
    """Control: this is the production failure. If a Python upgrade closes the window this
    test starts failing — keep loop_guard anyway (the backstop is cheap), but update the
    docstring there."""
    with pytest.raises(RuntimeError, match="Cannot close a running event loop"):
        asyncio.run(_value(1))
    monkeypatch.undo()
    assert events._get_running_loop() is not None
    coro = _value(2)
    with pytest.raises(RuntimeError, match="cannot be called from a running event loop"):
        asyncio.run(coro)
    coro.close()


def test_run_coroutine_survives_the_same_interrupt(interrupt_after_running_mark, monkeypatch):
    # The original exception comes out — not a RuntimeError from cleanup — so task.py's
    # `except SoftTimeLimitExceeded` still classifies it as a timeout.
    with pytest.raises(FakeSoftTimeLimit):
        loop_guard.run_coroutine(lambda: _value(1))
    monkeypatch.undo()
    assert events._get_running_loop() is None
    assert loop_guard.run_coroutine(lambda: _value(2)) == 2
    assert loop_guard.run_coroutine(lambda: _value(3)) == 3


def test_clears_a_mark_left_by_an_earlier_bare_asyncio_run(caplog):
    stale = asyncio.new_event_loop()
    try:
        events._set_running_loop(stale)   # a thread already poisoned the old way
        with caplog.at_level("ERROR", logger="loop_guard"):
            assert loop_guard.run_coroutine(lambda: _value(42)) == 42
        assert "still marked as running an event loop" in caplog.text
        assert events._get_running_loop() is None
    finally:
        events._set_running_loop(None)
        stale.close()


def test_interrupt_inside_the_loop_cancels_pending_work():
    state = {"cancelled": False}
    started = asyncio.Event()

    async def long_batch():
        started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    loops = []

    def factory():
        loop = asyncio.new_event_loop()
        real_run_once = loop._run_once

        def run_once():
            real_run_once()
            # Raise on the step that started the batch. Waiting for a later step would block
            # in select() for the batch's 3600s sleep.
            if started.is_set():
                loop._run_once = real_run_once
                raise FakeSoftTimeLimit()   # lands inside run_forever's try: cleanup runs

        loop._run_once = run_once
        loops.append(loop)
        return loop

    with pytest.raises(FakeSoftTimeLimit):
        loop_guard.run_coroutine(long_batch, loop_factory=factory, cancel_grace=5)
    assert state["cancelled"], "pending work was left running after the interrupt"
    assert loops[0].is_closed()
    assert events._get_running_loop() is None
    assert loop_guard.run_coroutine(lambda: _value("next task")) == "next task"


def test_normal_run_returns_value_and_leaves_thread_clean():
    assert loop_guard.run_coroutine(lambda: _value("ok")) == "ok"
    assert events._get_running_loop() is None


def test_exception_from_the_coroutine_propagates_unchanged():
    async def boom():
        await asyncio.sleep(0)
        raise ValueError("dns module failure")

    with pytest.raises(ValueError, match="dns module failure"):
        loop_guard.run_coroutine(boom)
    assert events._get_running_loop() is None
    assert loop_guard.run_coroutine(lambda: _value(1)) == 1
