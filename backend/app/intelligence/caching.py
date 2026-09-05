"""
Thread-safe In-Memory TTL LRU Cache for Threat Intelligence
Ensures bounded memory usage, automatic expiration, and high-concurrency safety.
"""

import time
import threading
from collections import OrderedDict
from typing import Any, Optional, Dict, Tuple


class TTLCache:
    """
    Least-Recently-Used (LRU) Cache with Time-To-Live (TTL) expiration per entry.
    Fully thread-safe via reentrant lock.
    """

    def __init__(self, maxsize: int = 1000, default_ttl: float = 3600.0):
        self.maxsize = max(1, maxsize)
        self.default_ttl = float(default_ttl)
        self._cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return default

            val, expiry = self._cache[key]
            now = time.time()
            if now > expiry:
                # Expired
                del self._cache[key]
                self._misses += 1
                return default

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return val

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        with self._lock:
            now = time.time()
            effective_ttl = float(ttl) if ttl is not None else self.default_ttl
            expiry = now + effective_ttl

            if key in self._cache:
                del self._cache[key]

            # Purge expired entries if at or above capacity
            if len(self._cache) >= self.maxsize:
                self._purge_expired(now)

            # If still at capacity, evict oldest (LRU)
            while len(self._cache) >= self.maxsize:
                self._cache.popitem(last=False)
                self._evictions += 1

            self._cache[key] = (value, expiry)

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "size": len(self._cache),
                "maxsize": self.maxsize,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
            }

    def _purge_expired(self, now: float) -> None:
        # Caller holds lock
        expired_keys = [k for k, (_, expiry) in self._cache.items() if now > expiry]
        for k in expired_keys:
            del self._cache[k]
