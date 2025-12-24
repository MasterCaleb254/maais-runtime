"""
Advanced Rate Limiting with Token Bucket and Sliding Windows
"""
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, deque
import asyncio
import threading


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_second: float = 10.0
    burst_size: int = 20
    window_seconds: int = 60
    algorithm: str = "token_bucket"  # token_bucket, sliding_window, fixed_window


class TokenBucket:
    """Token Bucket rate limiting algorithm"""
    
    def __init__(self, rate: float, capacity: int):
        """
        Args:
            rate: Tokens per second
            capacity: Maximum bucket size
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> Tuple[bool, float]:
        """
        Try to consume tokens
        
        Returns:
            (success, wait_time_seconds)
        """
        with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(self.capacity, self.tokens + time_passed * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, 0.0
            else:
                # Calculate wait time
                deficit = tokens - self.tokens
                wait_time = deficit / self.rate
                return False, wait_time
    
    def get_state(self) -> Dict:
        """Get current bucket state"""
        return {
            "tokens": self.tokens,
            "rate": self.rate,
            "capacity": self.capacity,
            "last_update": self.last_update
        }


class SlidingWindow:
    """Sliding Window rate limiting algorithm"""
    
    def __init__(self, max_requests: int, window_seconds: int):
        """
        Args:
            max_requests: Maximum requests in window
            window_seconds: Window size in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = deque()
        self.lock = threading.Lock()
    
    def add_request(self, timestamp: float = None) -> Tuple[bool, float]:
        """
        Add a request
        
        Returns:
            (success, wait_time_seconds)
        """
        with self.lock:
            now = timestamp or time.time()
            
            # Remove old requests outside window
            cutoff = now - self.window_seconds
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()
            
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True, 0.0
            else:
                # Calculate wait time until oldest request expires
                oldest = self.requests[0]
                wait_time = (oldest + self.window_seconds) - now
                return False, max(0.0, wait_time)
    
    def get_state(self) -> Dict:
        """Get current window state"""
        with self.lock:
            return {
                "current_requests": len(self.requests),
                "max_requests": self.max_requests,
                "window_seconds": self.window_seconds,
                "requests": list(self.requests)
            }


class AdvancedRateLimiter:
    """
    Advanced rate limiting with multiple algorithms and dimensions
    """
    
    def __init__(self):
        self.limiters: Dict[str, Dict] = defaultdict(dict)
        self.configs: Dict[str, Dict[str, RateLimitConfig]] = defaultdict(dict)
        self.history: Dict[str, List] = defaultdict(list)
        
        # Default configurations
        self.default_configs = {
            "global": RateLimitConfig(requests_per_second=100, burst_size=200),
            "per_agent": RateLimitConfig(requests_per_second=20, burst_size=50),
            "per_action": RateLimitConfig(requests_per_second=5, burst_size=10),
            "sensitive_actions": RateLimitConfig(requests_per_second=1, burst_size=3)
        }
    
    def get_limiter_key(self, dimension: str, identifier: str) -> str:
        """Create unique key for limiter"""
        return f"{dimension}:{identifier}"
    
    def setup_limiter(self, dimension: str, identifier: str, config: RateLimitConfig):
        """Setup rate limiter for dimension/identifier"""
        key = self.get_limiter_key(dimension, identifier)
        
        if config.algorithm == "token_bucket":
            limiter = TokenBucket(config.requests_per_second, config.burst_size)
        elif config.algorithm == "sliding_window":
            limiter = SlidingWindow(config.burst_size, config.window_seconds)
        else:
            raise ValueError(f"Unknown algorithm: {config.algorithm}")
        
        self.limiters[dimension][identifier] = limiter
        self.configs[dimension][identifier] = config
    
    def check_rate_limit(self, agent_id: str, action_type: str, target: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check rate limits across all dimensions
        
        Returns:
            (allowed, details)
        """
        dimensions_to_check = [
            ("global", "all"),
            ("per_agent", agent_id),
            ("per_action", action_type),
            ("sensitive", target if self._is_sensitive(target) else None)
        ]
        
        results = {}
        allowed = True
        wait_times = []
        
        for dimension, identifier in dimensions_to_check:
            if identifier is None:
                continue
            
            if dimension not in self.limiters or identifier not in self.limiters[dimension]:
                # Setup with default config
                config = self.default_configs.get(dimension, self.default_configs["global"])
                self.setup_limiter(dimension, identifier, config)
            
            limiter = self.limiters[dimension][identifier]
            
            if isinstance(limiter, TokenBucket):
                success, wait_time = limiter.consume()
            elif isinstance(limiter, SlidingWindow):
                success, wait_time = limiter.add_request()
            
            results[dimension] = {
                "allowed": success,
                "wait_time": wait_time,
                "limiter": limiter.__class__.__name__
            }
            
            if not success:
                allowed = False
                wait_times.append(wait_time)
        
        details = {
            "allowed": allowed,
            "results": results,
            "max_wait_time": max(wait_times) if wait_times else 0.0,
            "agent_id": agent_id,
            "action_type": action_type,
            "target": target
        }
        
        # Record in history
        self.history[agent_id].append({
            "timestamp": datetime.utcnow().isoformat(),
            "action_type": action_type,
            "target": target,
            "allowed": allowed,
            "details": results
        })
        
        # Trim history
        if len(self.history[agent_id]) > 1000:
            self.history[agent_id] = self.history[agent_id][-1000:]
        
        return allowed, details
    
    def _is_sensitive(self, target: str) -> bool:
        """Check if target is sensitive (requires stricter limits)"""
        sensitive_patterns = [
            "password", "secret", "token", "key",
            "delete", "drop", "truncate", "format",
            "execute", "sudo", "admin"
        ]
        
        target_lower = target.lower()
        return any(pattern in target_lower for pattern in sensitive_patterns)
    
    def get_limits_summary(self) -> Dict:
        """Get summary of all rate limiters"""
        summary = {
            "dimensions": {},
            "total_limiters": 0,
            "active_agents": len(set(
                identifier.split(":")[1] if ":" in identifier else identifier
                for dimension in self.limiters.values()
                for identifier in dimension.keys()
                if "per_agent" in identifier
            ))
        }
        
        for dimension, limiters in self.limiters.items():
            summary["dimensions"][dimension] = {
                "count": len(limiters),
                "configs": {
                    identifier: {
                        "algorithm": self.configs[dimension][identifier].algorithm,
                        "requests_per_second": self.configs[dimension][identifier].requests_per_second,
                        "burst_size": self.configs[dimension][identifier].burst_size
                    }
                    for identifier in limiters.keys()
                    if identifier in self.configs[dimension]
                }
            }
            summary["total_limiters"] += len(limiters)
        
        return summary
    
    def get_agent_rate_stats(self, agent_id: str) -> Dict:
        """Get rate limiting statistics for agent"""
        if agent_id not in self.history:
            return {"error": "No history found"}
        
        history = self.history[agent_id]
        recent = history[-100:] if len(history) > 100 else history
        
        # Calculate statistics
        total_requests = len(recent)
        blocked_requests = sum(1 for h in recent if not h["allowed"])
        allowed_requests = total_requests - blocked_requests
        
        # Calculate requests per minute
        if len(recent) >= 2:
            time_span = (
                datetime.fromisoformat(recent[-1]["timestamp"]) - 
                datetime.fromisoformat(recent[0]["timestamp"])
            ).total_seconds() / 60.0  # minutes
            
            if time_span > 0:
                rpm = len(recent) / time_span
            else:
                rpm = len(recent)
        else:
            rpm = 0
        
        return {
            "agent_id": agent_id,
            "total_requests": total_requests,
            "allowed_requests": allowed_requests,
            "blocked_requests": blocked_requests,
            "block_rate": blocked_requests / total_requests if total_requests > 0 else 0,
            "requests_per_minute": rpm,
            "recent_history": recent[-10:]  # Last 10 requests
        }
    
    def reset_limits(self, dimension: str = None, identifier: str = None):
        """Reset rate limits"""
        if dimension is None:
            # Reset all
            self.limiters.clear()
            self.configs.clear()
            print("Reset all rate limiters")
        elif identifier is None:
            # Reset dimension
            if dimension in self.limiters:
                del self.limiters[dimension]
            if dimension in self.configs:
                del self.configs[dimension]
            print(f"Reset dimension: {dimension}")
        else:
            # Reset specific limiter
            key = self.get_limiter_key(dimension, identifier)
            if dimension in self.limiters and identifier in self.limiters[dimension]:
                del self.limiters[dimension][identifier]
            if dimension in self.configs and identifier in self.configs[dimension]:
                del self.configs[dimension][identifier]
            print(f"Reset limiter: {key}")


# Async version for async applications
class AsyncRateLimiter(AdvancedRateLimiter):
    """Async version of rate limiter"""
    
    async def check_rate_limit_async(self, agent_id: str, action_type: str, target: str) -> Tuple[bool, Dict]:
        """Async version of check_rate_limit"""
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self.check_rate_limit, agent_id, action_type, target
        )