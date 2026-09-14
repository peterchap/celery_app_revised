"""Run one coroutine per Celery task without an interrupted loop poisoning the worker.

WHY THIS EXISTS (2026-09-07..09-11, resolver 10.0.0.62).
task.py used to call asyncio.run() directly. Celery enforces soft_time_limit by raising
SoftTimeLimitExceeded from a signal handler, i.e. at whatever bytecode the worker happens to
be executing. In CPython 3.14, BaseEventLoop.run_forever() calls _run_forever_setup() BEFORE
entering the try whose finally runs _run_forever_cleanup(). setup's last statement marks the
thread as running the loop. A signal landing after that mark and before the try skips cleanup:

    first run   RuntimeError: Cannot close a running event loop
                 <- This event loop is already running <- SoftTimeLimitExceeded
    every later RuntimeError: asyncio.run() cannot be called from a running event loop

The pool child is long-lived (--concurrency=1, no max_tasks_per_child), so every later task
in that process failed within milliseconds. Failing that fast, one worker took most of the
tasks off the shared queues: 119,371 failures in four days while 16 healthy workers starved,
~44M refresh lookups ended in failed/, and nothing alerted. Reproduced deterministically on
3.14.3 by raising the exception immediately after the running-loop mark is set
(tests/test_loop_guard.py).

WHAT THIS DOES DIFFERENTLY from asyncio.run():
  * clears a running-loop mark left behind by an earlier task before starting, and logs it;
  * on any exception out of the loop, cancels the coroutine's pending work inside the loop,
    bounded by a grace period so it finishes before Celery's hard time_limit;
  * always clears the mark afterwards, and never lets a cleanup error replace the original
    exception, so task.py's `except SoftTimeLimitExceeded` still sees a timeout as a timeout.

It uses asyncio.events._get_running_loop/_set_running_loop. They are underscored but listed
in asyncio.events.__all__ and are what event-loop implementations themselves call.

celeryconfig.worker_max_tasks_per_child is the backstop for poison states this does not
know about. Keep both.
"""
from __future__ import annotations

import asyncio
import logging
from asyncio import events
from typing import Any, Awaitable, Callable

log = logging.getLogger(__name__)

# asyncio.run() waits up to 300s for the default executor; that would overrun the 300s gap
# between soft_time_limit and time_limit in task.py, so interrupted runs get less.
CANCEL_GRACE_SECONDS = 30.0
EXECUTOR_JOIN_SECONDS_NORMAL = 300.0
EXECUTOR_JOIN_SECONDS_INTERRUPTED = 30.0


def clear_leftover_running_loop() -> bool:
    """Drop this thread's running-loop mark if one is still set. True if it was."""
    if events._get_running_loop() is None:
        return False
    events._set_running_loop(None)
    return True


def run_coroutine(
    make_coro: Callable[[], Awaitable[Any]],
    *,
    loop_factory: Callable[[], asyncio.AbstractEventLoop] = asyncio.new_event_loop,
    cancel_grace: float = CANCEL_GRACE_SECONDS,
) -> Any:
    """asyncio.run(make_coro()) that cannot leave the worker thread poisoned.

    Takes a factory rather than a coroutine so nothing is created (and left un-awaited)
    before the loop exists.
    """
    if clear_leftover_running_loop():
        log.error(
            "Worker thread was still marked as running an event loop from an earlier task "
            "(an interrupt landed inside run_forever's setup/cleanup). Cleared it; without "
            "this every task in this process would fail instantly."
        )

    loop = loop_factory()
    interrupted = False
    try:
        events.set_event_loop(loop)
        main = loop.create_task(make_coro())
        return loop.run_until_complete(main)
    except BaseException:
        interrupted = True
        raise
    finally:
        # The line that matters: whatever happened above, this thread is not running a loop.
        events._set_running_loop(None)
        _shutdown(loop, interrupted=interrupted, cancel_grace=cancel_grace)
        events._set_running_loop(None)
        events.set_event_loop(None)


def _shutdown(loop: asyncio.AbstractEventLoop, *, interrupted: bool, cancel_grace: float) -> None:
    """Cancel leftover tasks, drain async generators and the executor, close the loop.

    Never raises: an error here must not mask the exception that ended the task.
    """
    if loop.is_closed():
        return
    if loop.is_running():
        # Interrupted inside run_forever's own setup/cleanup: the loop still believes it is
        # running, so it can neither be run again nor closed. Abandon it; its sockets are
        # released when the pool child is recycled.
        log.warning("Abandoning an event loop left in the running state by an interrupt.")
        return
    try:
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            wait = asyncio.wait(pending, timeout=cancel_grace if interrupted else None)
            loop.run_until_complete(wait)
        loop.run_until_complete(loop.shutdown_asyncgens())
        join = EXECUTOR_JOIN_SECONDS_INTERRUPTED if interrupted else EXECUTOR_JOIN_SECONDS_NORMAL
        loop.run_until_complete(loop.shutdown_default_executor(join))
    except BaseException as exc:  # includes a second soft-limit signal during cleanup
        log.warning("Event loop shutdown did not complete cleanly: %r", exc)
    finally:
        events._set_running_loop(None)
        if not loop.is_running():
            try:
                loop.close()
            except BaseException as exc:
                log.warning("Event loop close failed: %r", exc)
