"""
Performance Optimizations for MAAIS-Runtime
Caching, memoization, and async optimizations
"""
import functools
import time
import hashlib
import json
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import OrderedDict
import asyncio
import threading
import pickle


@dataclass
class CacheEntry:
    """Cache entry with expiration"""
    key: str
    value: Any
    created_at: float
    expires_at: Optional[float] = None
    hits: int = 0
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    def __repr__(self) -> str:
        age = time.time() - self.created_at
        return f"CacheEntry(key={self.key[:20]}..., age={age:.1f}s, hits={self.hits})"


class LRUCache:
    """
    LRU (Least Recently Used) Cache with TTL support
    """
    
    def __init__(self, maxsize: int = 1000, ttl: Optional[float] = None):
        """
        Args:
            maxsize: Maximum number of cache entries
            ttl: Time to live in seconds (None = no expiration)
        """
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache: Dict[str, CacheEntry] = {}
        self.order: List[str] = []
        self.hits = 0
        self.misses = 0
        self.lock = threading.RLock()
        
        print(f"LRUCache initialized: maxsize={maxsize}, ttl={ttl}")
    
    def _make_key(self, *args, **kwargs) -> str:
        """Create cache key from function arguments"""
        try:
            # Try to create a deterministic key
            key_parts = []
            
            # Add args
            for arg in args:
                if isinstance(arg, (str, int, float, bool, type(None))):
                    key_parts.append(str(arg))
                else:
                    key_parts.append(hashlib.md5(pickle.dumps(arg)).hexdigest())
            
            # Add kwargs
            for key, value in sorted(kwargs.items()):
                if isinstance(value, (str, int, float, bool, type(None))):
                    key_parts.append(f"{key}:{value}")
                else:
                    key_parts.append(f"{key}:{hashlib.md5(pickle.dumps(value)).hexdigest()}")
            
            return hashlib.md5("|".join(key_parts).encode()).hexdigest()
        
        except Exception:
            # Fallback to simple hash
            return hashlib.md5(str((args, kwargs)).encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                
                if entry.is_expired():
                    # Remove expired entry
                    del self.cache[key]
                    self.order.remove(key)
                    self.misses += 1
                    return None
                
                # Update LRU order
                self.order.remove(key)
                self.order.append(key)
                
                entry.hits += 1
                self.hits += 1
                return entry.value
            
            self.misses += 1
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None):
        """Set value in cache"""
        with self.lock:
            expires_at = None
            if ttl is not None:
                expires_at = time.time() + ttl
            elif self.ttl is not None:
                expires_at = time.time() + self.ttl
            
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=time.time(),
                expires_at=expires_at
            )
            
            if key in self.cache:
                # Update existing
                self.cache[key] = entry
                self.order.remove(key)
                self.order.append(key)
            else:
                # Add new
                if len(self.cache) >= self.maxsize:
                    # Remove oldest
                    oldest_key = self.order.pop(0)
                    del self.cache[oldest_key]
                
                self.cache[key] = entry
                self.order.append(key)
    
    def delete(self, key: str):
        """Delete key from cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                self.order.remove(key)
    
    def clear(self):
        """Clear all cache"""
        with self.lock:
            self.cache.clear()
            self.order.clear()
            self.hits = 0
            self.misses = 0
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self.lock:
            total = self.hits + self.misses
            hit_rate = self.hits / total if total > 0 else 0
            
            # Count expired entries
            expired = sum(1 for entry in self.cache.values() if entry.is_expired())
            
            return {
                "size": len(self.cache),
                "maxsize": self.maxsize,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": hit_rate,
                "expired_entries": expired,
                "total_requests": total,
                "avg_hits_per_entry": (
                    sum(entry.hits for entry in self.cache.values()) / len(self.cache)
                    if self.cache else 0
                )
            }
    
    def get_most_used(self, n: int = 10) -> List[Dict]:
        """Get most frequently used entries"""
        with self.lock:
            entries = sorted(
                self.cache.values(),
                key=lambda e: e.hits,
                reverse=True
            )[:n]
            
            return [{
                "key": e.key[:50] + ("..." if len(e.key) > 50 else ""),
                "hits": e.hits,
                "age_seconds": time.time() - e.created_at,
                "expired": e.is_expired()
            } for e in entries]


def cached(maxsize: int = 1000, ttl: Optional[float] = None):
    """
    Decorator for caching function results
    
    Args:
        maxsize: Maximum cache size
        ttl: Time to live in seconds
    """
    def decorator(func: Callable):
        cache = LRUCache(maxsize=maxsize, ttl=ttl)
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = cache._make_key(func.__name__, *args, **kwargs)
            cached_value = cache.get(key)
            
            if cached_value is not None:
                return cached_value
            
            result = func(*args, **kwargs)
            cache.set(key, result)
            return result
        
        # Attach cache to function for inspection
        wrapper.cache = cache
        
        return wrapper
    
    return decorator


class PolicyCache:
    """
    Specialized cache for policy evaluation
    """
    
    def __init__(self):
        self.action_cache = LRUCache(maxsize=10000, ttl=300)  # 5 minutes
        self.policy_cache = LRUCache(maxsize=1000, ttl=600)  # 10 minutes
        self.rate_limit_cache = LRUCache(maxsize=5000, ttl=60)  # 1 minute
        
        print("PolicyCache initialized")
    
    def get_action_decision(
        self,
        action_hash: str,
        agent_id: str,
        action_type: str,
        target: str
    ) -> Optional[Tuple[bool, str]]:
        """Get cached action decision"""
        key = f"decision:{agent_id}:{action_type}:{target}:{action_hash}"
        return self.action_cache.get(key)
    
    def set_action_decision(
        self,
        action_hash: str,
        agent_id: str,
        action_type: str,
        target: str,
        decision: bool,
        reason: str
    ):
        """Cache action decision"""
        key = f"decision:{agent_id}:{action_type}:{target}:{action_hash}"
        self.action_cache.set(key, (decision, reason), ttl=300)
    
    def get_policy_result(self, policy_id: str, action_hash: str) -> Optional[bool]:
        """Get cached policy evaluation result"""
        key = f"policy:{policy_id}:{action_hash}"
        return self.policy_cache.get(key)
    
    def set_policy_result(self, policy_id: str, action_hash: str, result: bool):
        """Cache policy evaluation result"""
        key = f"policy:{policy_id}:{action_hash}"
        self.policy_cache.set(key, result, ttl=600)
    
    def get_rate_limit(self, key: str) -> Optional[Tuple[bool, float]]:
        """Get cached rate limit result"""
        return self.rate_limit_cache.get(key)
    
    def set_rate_limit(self, key: str, allowed: bool, wait_time: float):
        """Cache rate limit result"""
        self.rate_limit_cache.set(key, (allowed, wait_time), ttl=60)
    
    def invalidate_agent(self, agent_id: str):
        """Invalidate all cache entries for agent"""
        keys_to_delete = []
        
        # Scan action cache
        for key in list(self.action_cache.cache.keys()):
            if f":{agent_id}:" in key:
                keys_to_delete.append(key)
        
        for key in keys_to_delete:
            self.action_cache.delete(key)
        
        print(f"Invalidated cache for agent {agent_id}: {len(keys_to_delete)} entries")
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            "action_cache": self.action_cache.get_stats(),
            "policy_cache": self.policy_cache.get_stats(),
            "rate_limit_cache": self.rate_limit_cache.get_stats(),
            "total_size": (
                self.action_cache.get_stats()["size"] +
                self.policy_cache.get_stats()["size"] +
                self.rate_limit_cache.get_stats()["size"]
            )
        }


class AsyncBatchProcessor:
    """
    Batch process actions asynchronously for better performance
    """
    
    def __init__(self, batch_size: int = 10, max_wait: float = 0.1):
        """
        Args:
            batch_size: Maximum batch size
            max_wait: Maximum wait time before processing batch (seconds)
        """
        self.batch_size = batch_size
        self.max_wait = max_wait
        self.batch: List[Tuple[Any, asyncio.Future]] = []
        self.last_process_time = time.time()
        self.lock = asyncio.Lock()
        self.processing = False
        
        print(f"AsyncBatchProcessor initialized: batch_size={batch_size}, max_wait={max_wait}")
    
    async def add_to_batch(self, item: Any) -> Any:
        """
        Add item to batch, return result when processed
        
        Args:
            item: Item to process
        
        Returns:
            Processing result
        """
        future = asyncio.Future()
        
        async with self.lock:
            self.batch.append((item, future))
            
            # Check if we should process
            should_process = (
                len(self.batch) >= self.batch_size or
                (time.time() - self.last_process_time) >= self.max_wait
            )
        
        if should_process and not self.processing:
            asyncio.create_task(self._process_batch())
        
        return await future
    
    async def _process_batch(self):
        """Process the current batch"""
        if self.processing:
            return
        
        self.processing = True
        
        async with self.lock:
            batch = self.batch.copy()
            self.batch.clear()
        
        if not batch:
            self.processing = False
            return
        
        try:
            # Process batch (this should be overridden by subclass)
            results = await self._process_items([item for item, _ in batch])
            
            # Set results on futures
            for (item, future), result in zip(batch, results):
                if not future.done():
                    future.set_result(result)
        
        except Exception as e:
            # Set exception on all futures
            for _, future in batch:
                if not future.done():
                    future.set_exception(e)
        
        finally:
            self.last_process_time = time.time()
            self.processing = False
    
    async def _process_items(self, items: List[Any]) -> List[Any]:
        """
        Process items - to be overridden by subclass
        
        Args:
            items: List of items to process
        
        Returns:
            List of results
        """
        # Default implementation - just return items
        return items
    
    async def flush(self):
        """Force process current batch"""
        if self.batch:
            await self._process_batch()


class PolicyBatchProcessor(AsyncBatchProcessor):
    """Batch processor for policy evaluations"""
    
    def __init__(self, policy_engine, batch_size: int = 20, max_wait: float = 0.05):
        super().__init__(batch_size, max_wait)
        self.policy_engine = policy_engine
    
    async def _process_items(self, actions: List) -> List[Optional[str]]:
        """Batch evaluate policies for multiple actions"""
        # This is a simplified example - in reality you'd need to
        # adapt your policy engine to support batch evaluation
        
        results = []
        for action in actions:
            result = self.policy_engine.evaluate(action)
            results.append(result)
        
        return results