"""In-memory ring buffer for recent attack events.

The buffer is deliberately small and non-persistent: this is a public,
near-real-time feed, not a SIEM. Events that age out of the buffer or out
of the configured window are simply dropped from the response.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta, timezone

from .models import AttackEvent


class EventBuffer:
    def __init__(self, maxlen: int, window_seconds: int) -> None:
        self._events: deque[AttackEvent] = deque(maxlen=maxlen)
        self._window = timedelta(seconds=window_seconds)
        self._lock = threading.Lock()

    def push(self, event: AttackEvent) -> None:
        with self._lock:
            self._events.append(event)

    def recent(self) -> list[AttackEvent]:
        cutoff = datetime.now(timezone.utc) - self._window
        with self._lock:
            # `deque` isn't a great fit for filtering, but N is bounded by
            # `event_buffer_size` (default 500) so the cost is negligible.
            return [e for e in self._events if e.ts >= cutoff]

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
