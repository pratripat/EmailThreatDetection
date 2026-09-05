"""
SQLite URL Cache
Provides persistent, TTL-aware local caching for URL threat analyses,
indexed by SHA-256 hashes to prevent redundant AI queries and optimize latency.
"""

import sqlite3
import hashlib
import json
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from config import settings

logger = logging.getLogger("url_cache")


class URLCache:
    """Persistent SQLite-backed cache for URL threat evaluations."""

    def __init__(self, db_path: Optional[Path] = None, default_ttl: Optional[int] = None):
        self.db_path = db_path or settings.CACHE_DB_PATH
        self.default_ttl = default_ttl or settings.CACHE_TTL_SECONDS
        self._ensure_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Create a connection with WAL mode and reasonable timeout."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _ensure_db(self) -> None:
        """Initialize cache table and indices if not present."""
        try:
            with self._get_conn() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS url_cache (
                        url_hash TEXT PRIMARY KEY,
                        url TEXT NOT NULL,
                        domain TEXT,
                        threat_score INTEGER,
                        reputation TEXT,
                        verdict TEXT,
                        confidence REAL,
                        reason TEXT,
                        flags_json TEXT,
                        created_at REAL,
                        expires_at REAL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_expires_at ON url_cache(expires_at)")
        except Exception as e:
            logger.error(f"Failed to initialize SQLite URL cache at {self.db_path}: {e}")

    @staticmethod
    def hash_url(url: str) -> str:
        """Compute SHA-256 hash of a normalized URL string."""
        normalized = url.strip().encode("utf-8")
        return hashlib.sha256(normalized).hexdigest()

    def get(self, url: str) -> Optional[Dict[str, Any]]:
        """Retrieve unexpired analysis result for a given URL."""
        url_hash = self.hash_url(url)
        now = time.time()
        try:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    "SELECT * FROM url_cache WHERE url_hash = ? AND expires_at > ?",
                    (url_hash, now)
                )
                row = cursor.fetchone()
                if not row:
                    return None

                flags = []
                if row["flags_json"]:
                    try:
                        flags = json.loads(row["flags_json"])
                    except Exception:
                        pass

                return {
                    "url": row["url"],
                    "domain": row["domain"],
                    "threatScore": row["threat_score"],
                    "reputation": row["reputation"],
                    "flags": flags,
                    "grok_analysis": {
                        "verdict": row["verdict"],
                        "confidence": row["confidence"],
                        "reason": row["reason"],
                    } if row["verdict"] else None,
                    "cached": True,
                    "created_at": row["created_at"],
                    "expires_at": row["expires_at"]
                }
        except Exception as e:
            logger.warning(f"Cache lookup failed for URL '{url}': {e}")
            return None

    def set(self, url: str, result: Dict[str, Any], ttl_seconds: Optional[int] = None) -> bool:
        """Save analysis result to SQLite with TTL."""
        url_hash = self.hash_url(url)
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = now + ttl

        grok = result.get("grok_analysis") or {}
        verdict = grok.get("verdict")
        confidence = grok.get("confidence")
        reason = grok.get("reason")
        flags = result.get("flags", [])
        flags_json = json.dumps(flags)

        try:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO url_cache (
                        url_hash, url, domain, threat_score, reputation,
                        verdict, confidence, reason, flags_json,
                        created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    url_hash,
                    url,
                    result.get("domain", ""),
                    result.get("threatScore", 0),
                    result.get("reputation", "UNKNOWN"),
                    verdict,
                    confidence,
                    reason,
                    flags_json,
                    now,
                    expires_at
                ))
            return True
        except Exception as e:
            logger.warning(f"Failed to cache result for URL '{url}': {e}")
            return False

    def clear_expired(self) -> int:
        """Delete all expired cache entries. Returns count of deleted rows."""
        now = time.time()
        try:
            with self._get_conn() as conn:
                cursor = conn.execute("DELETE FROM url_cache WHERE expires_at <= ?", (now,))
                return cursor.rowcount
        except Exception as e:
            logger.error(f"Error purging expired cache records: {e}")
            return 0


_default_cache: Optional[URLCache] = None


def get_url_cache() -> URLCache:
    """Get singleton URLCache instance."""
    global _default_cache
    if _default_cache is None:
        _default_cache = URLCache()
    return _default_cache
