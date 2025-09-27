"""Simple caching utilities for evergreen-python."""

import json
import os
import time
from typing import Any, Optional, Dict
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class SimpleCache:
    """Simple file-based cache with TTL support."""

    def __init__(self, cache_dir: str = "/tmp/evergreen-cache", default_ttl: int = 3600):
        """Initialize cache.

        Args:
            cache_dir: Directory to store cache files
            default_ttl: Default TTL in seconds
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl

    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for key.

        Args:
            key: Cache key

        Returns:
            Path to cache file
        """
        # Simple key sanitization
        safe_key = key.replace("/", "_").replace(":", "_")
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)

            # Check TTL
            if time.time() > cache_data.get('expires_at', 0):
                # Cache expired, remove file
                cache_path.unlink(missing_ok=True)
                return None

            return cache_data.get('value')

        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.warning(f"Failed to read cache for key {key}: {e}")
            # Remove corrupted cache file
            cache_path.unlink(missing_ok=True)
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL in seconds (use default if None)
        """
        if ttl is None:
            ttl = self.default_ttl

        cache_path = self._get_cache_path(key)
        expires_at = time.time() + ttl

        cache_data = {
            'value': value,
            'expires_at': expires_at,
            'created_at': time.time()
        }

        try:
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)

        except (OSError, json.JSONEncodeError) as e:
            logger.warning(f"Failed to write cache for key {key}: {e}")

    def delete(self, key: str) -> None:
        """Delete value from cache.

        Args:
            key: Cache key
        """
        cache_path = self._get_cache_path(key)
        cache_path.unlink(missing_ok=True)

    def clear(self) -> None:
        """Clear all cache entries."""
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink(missing_ok=True)

    def cleanup_expired(self) -> int:
        """Clean up expired cache entries.

        Returns:
            Number of entries cleaned up
        """
        cleaned_count = 0
        current_time = time.time()

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)

                if current_time > cache_data.get('expires_at', 0):
                    cache_file.unlink()
                    cleaned_count += 1

            except (json.JSONDecodeError, KeyError, OSError):
                # Remove corrupted files
                cache_file.unlink(missing_ok=True)
                cleaned_count += 1

        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} expired cache entries")

        return cleaned_count


# Global cache instance
_cache = None


def get_cache() -> SimpleCache:
    """Get global cache instance.

    Returns:
        Cache instance
    """
    global _cache
    if _cache is None:
        cache_dir = os.getenv("CACHE_DIR", "/tmp/evergreen-cache")
        default_ttl = int(os.getenv("CACHE_TTL", "3600"))
        _cache = SimpleCache(cache_dir, default_ttl)
    return _cache