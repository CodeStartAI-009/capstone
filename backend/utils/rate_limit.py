"""Minimal in-memory sliding-window rate limiter (per client address).

Adequate for a single-process local deployment; a multi-process deployment
would need a shared store (e.g. Redis) instead. See docs/api.md ("Security considerations").
"""
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_requests, window_seconds=60.0, clock=time.monotonic):
        self.max_requests = max_requests
        self.window = window_seconds
        self.clock = clock
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key):
        """Record a hit; return (allowed, retry_after_seconds)."""
        if self.max_requests <= 0:
            return True, 0
        now = self.clock()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.max_requests:
                return False, max(1, int(self.window - (now - hits[0])) + 1)
            hits.append(now)
            if len(self._hits) > 10_000:  # bound memory: drop idle clients
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True, 0
