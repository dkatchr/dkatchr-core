"""
Token-bucket rate limiter — thread-safe.

MOVED FROM: dkatchr/ratelimit.py
WHY: Lives with the HTTP clients that actually use it. No public-API change —
re-exported via clients/__init__.py-free path imports still work.
"""

import threading
import time


class TokenBucket:
    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate     = float(rate)
        self.capacity = float(capacity) if capacity is not None else self.rate
        self.tokens   = self.capacity
        self.last     = time.monotonic()
        self.lock     = threading.Lock()

    def acquire(self) -> None:
        """Block until one token is available, then consume it."""
        while True:
            with self.lock:
                now           = time.monotonic()
                elapsed       = now - self.last
                self.last     = now
                self.tokens   = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            time.sleep(wait)
