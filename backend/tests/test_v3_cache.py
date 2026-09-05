import time
from backend.app.intelligence.caching import TTLCache


def test_cache_basic_get_set():
    cache = TTLCache(maxsize=10, default_ttl=5.0)
    cache.set("foo", "bar")
    assert cache.get("foo") == "bar"
    assert cache.get("missing") is None
    assert cache.get("missing", "default") == "default"


def test_cache_expiration():
    cache = TTLCache(maxsize=10, default_ttl=0.1)
    cache.set("temp", 123)
    assert cache.get("temp") == 123
    time.sleep(0.15)
    assert cache.get("temp") is None


def test_cache_lru_eviction():
    cache = TTLCache(maxsize=2, default_ttl=10.0)
    cache.set("a", 1)
    cache.set("b", 2)
    # Access "a" so "b" is LRU
    assert cache.get("a") == 1
    cache.set("c", 3)
    # "b" should be evicted
    assert cache.get("b") is None
    assert cache.get("a") == 1
    assert cache.get("c") == 3


def test_cache_stats():
    cache = TTLCache(maxsize=5, default_ttl=5.0)
    cache.set("k1", "v1")
    cache.get("k1")  # hit
    cache.get("k2")  # miss
    stats = cache.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["size"] == 1
