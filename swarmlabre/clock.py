"""The one place wall-clock time is read. Everything that stamps a time (findings, events, reports) calls `now()`.

Live, `now()` is `time.time()`. A thread can *pin* it (`with pinned(t):`) so that a piece of work sees one fixed time: the run records that time next to the work's
inputs, and a replay pins the same value, which is what makes the stamps (and everything built from them) come out identical. Pinning is per thread.
"""
import threading
import time
from contextlib import contextmanager

_local = threading.local()


def now():
    v = getattr(_local, "t", None)
    return time.time() if v is None else v


def real():
    """The true time, ignoring any pin (what a recorder writes down before it pins)."""
    return time.time()


@contextmanager
def pinned(t):
    prev = getattr(_local, "t", None)
    _local.t = float(t)
    try:
        yield
    finally:
        _local.t = prev


def utc(t, fmt="%Y-%m-%d %H:%M:%S"):
    """`t` as UTC text. Never local time: a report must not change with the machine's time zone."""
    return time.strftime(fmt, time.gmtime(t))
