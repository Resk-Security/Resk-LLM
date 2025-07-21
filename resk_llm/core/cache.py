"""
Intelligent caching system for RESK-LLM security components.

This module provides high-performance caching for security filters, detectors,
and other computationally expensive operations to improve response times.
"""

import time
import hashlib
import threading
from typing import Dict, Any, Optional, Tuple, Union, List
from dataclasses import dataclass
from collections import OrderedDict
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

@dataclass
class CacheEntry:
    """Represents a cached result with metadata."""
    value: Any
    timestamp: float
    access_count: int = 0
    hash_key: str = ""
    component_version: str = "1.0.0"
    
    def is_expired(self, ttl: float) -> bool:
        """Check if the cache entry has expired."""
        return time.time() - self.timestamp > ttl
    
    def touch(self) -> None:
        """Update access count and timestamp."""
        self.access_count += 1
        self.timestamp = time.time()

class IntelligentCache:
    """
    High-performance cache with intelligent eviction, TTL, and thread safety.
    Optimized for security component results.
    """
    
    def __init__(self, 
                 max_size: int = 10000,
                 default_ttl: float = 3600.0,  # 1 hour
                 cleanup_interval: float = 300.0,  # 5 minutes
                 enable_stats: bool = True):
        """
        Initialize the intelligent cache.
        
        Args:
            max_size: Maximum number of cached entries
            default_ttl: Default time-to-live in seconds
            cleanup_interval: Interval for automatic cleanup in seconds
            enable_stats: Whether to track cache statistics
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        self.enable_stats = enable_stats
        
        # Thread-safe cache storage
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        
        # Statistics tracking
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expired_removals': 0,
            'total_sets': 0
        }
        
        # Last cleanup timestamp
        self._last_cleanup = time.time()
        
        # Component-specific TTL overrides
        self._component_ttls: Dict[str, float] = {
            'HeuristicFilter': 1800.0,  # 30 minutes
            'VectorDatabase': 3600.0,   # 1 hour
            'CanaryTokenDetector': 7200.0,  # 2 hours
            'TextAnalyzer': 900.0,      # 15 minutes
            'URLDetector': 1800.0,      # 30 minutes
            'IPDetector': 3600.0,       # 1 hour
        }
    
    def __len__(self) -> int:
        """Return the number of cached entries."""
        with self._lock:
            return len(self._cache)
    
    def _generate_key(self, component_name: str, input_data: Any, **kwargs) -> str:
        """Generate a unique cache key for the given input."""
        try:
            # Create a deterministic hash from input data
            if isinstance(input_data, str):
                data_str = input_data
            else:
                data_str = json.dumps(input_data, sort_keys=True, default=str)
            
            # Include component name and kwargs in the key
            key_data = f"{component_name}:{data_str}:{json.dumps(kwargs, sort_keys=True, default=str)}"
            
            # Generate SHA256 hash for consistent key length
            return hashlib.sha256(key_data.encode('utf-8')).hexdigest()
            
        except Exception as e:
            logger.warning(f"Error generating cache key: {e}")
            # Fallback to simple string representation
            return f"{component_name}:{hash(str(input_data))}"
    
    def get(self, key: str, default: Any = None) -> Optional[Any]:
        """
        Retrieve a cached result using a simple key.
        
        Args:
            key: The cache key
            default: Default value if key not found
            
        Returns:
            Cached result or default if not found/expired
        """
        with self._lock:
            # Check if we need cleanup
            if time.time() - self._last_cleanup > self.cleanup_interval:
                self._cleanup_expired()
            
            entry = self._cache.get(key)
            if entry is None:
                if self.enable_stats:
                    self._stats['misses'] += 1
                return default
            
            # Check if expired
            ttl = self.default_ttl
            if entry.is_expired(ttl):
                del self._cache[key]
                if self.enable_stats:
                    self._stats['misses'] += 1
                    self._stats['expired_removals'] += 1
                return default
            
            # Update access info and move to end (LRU)
            entry.touch()
            self._cache.move_to_end(key)
            
            if self.enable_stats:
                self._stats['hits'] += 1
            
            return entry.value
    
    def get_component(self, component_name: str, input_data: Any, **kwargs) -> Optional[Any]:
        """
        Retrieve a cached result for a component.
        
        Args:
            component_name: Name of the security component
            input_data: Input data used to generate the cache key
            **kwargs: Additional parameters for cache key generation
            
        Returns:
            Cached result or None if not found/expired
        """
        key = self._generate_key(component_name, input_data, **kwargs)
        
        with self._lock:
            # Check if we need cleanup
            if time.time() - self._last_cleanup > self.cleanup_interval:
                self._cleanup_expired()
            
            entry = self._cache.get(key)
            if entry is None:
                if self.enable_stats:
                    self._stats['misses'] += 1
                return None
            
            # Check if expired
            ttl = self._component_ttls.get(component_name, self.default_ttl)
            if entry.is_expired(ttl):
                del self._cache[key]
                if self.enable_stats:
                    self._stats['misses'] += 1
                    self._stats['expired_removals'] += 1
                return None
            
            # Update access info and move to end (LRU)
            entry.touch()
            self._cache.move_to_end(key)
            
            if self.enable_stats:
                self._stats['hits'] += 1
            
            return entry.value
    
    def set(self, key: str, value: Any, **kwargs) -> None:
        """
        Store a result in the cache using a simple key.
        
        Args:
            key: The cache key
            value: Value to cache
            **kwargs: Additional parameters
        """
        with self._lock:
            # Check if we need to evict entries
            if len(self._cache) >= self.max_size:
                self._evict_lru()
            
            # Store the new entry
            entry = CacheEntry(
                value=value,
                timestamp=time.time(),
                hash_key=key
            )
            
            self._cache[key] = entry
            
            if self.enable_stats:
                self._stats['total_sets'] += 1
    
    def set_component(self, component_name: str, input_data: Any, result: Any, **kwargs) -> None:
        """
        Store a result in the cache for a component.
        
        Args:
            component_name: Name of the security component
            input_data: Input data used to generate the cache key
            result: Result to cache
            **kwargs: Additional parameters for cache key generation
        """
        key = self._generate_key(component_name, input_data, **kwargs)
        
        with self._lock:
            # Check if we need to evict entries
            if len(self._cache) >= self.max_size:
                self._evict_lru()
            
            # Store the new entry
            entry = CacheEntry(
                value=result,
                timestamp=time.time(),
                hash_key=key
            )
            
            self._cache[key] = entry
            
            if self.enable_stats:
                self._stats['total_sets'] += 1
    
    def delete(self, key: str) -> None:
        """Delete a specific key from the cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
    
    def _evict_lru(self) -> None:
        """Evict the least recently used entry."""
        if self._cache:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
            if self.enable_stats:
                self._stats['evictions'] += 1
    
    def _cleanup_expired(self) -> None:
        """Remove expired entries from the cache."""
        current_time = time.time()
        expired_keys = []
        
        for key, entry in self._cache.items():
            # Get component name from key (first part before colon)
            component_name = key.split(':', 1)[0] if ':' in key else 'default'
            ttl = self._component_ttls.get(component_name, self.default_ttl)
            
            if entry.is_expired(ttl):
                expired_keys.append(key)
        
        # Remove expired entries
        for key in expired_keys:
            del self._cache[key]
            if self.enable_stats:
                self._stats['expired_removals'] += 1
        
        self._last_cleanup = current_time
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
            logger.info("Cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            hit_rate = 0.0
            total_requests = self._stats['hits'] + self._stats['misses']
            if total_requests > 0:
                hit_rate = self._stats['hits'] / total_requests
            
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hit_rate': hit_rate,
                'total_requests': total_requests,
                **self._stats
            }
    
    def optimize_for_component(self, component_name: str, ttl: float) -> None:
        """
        Optimize cache settings for a specific component.
        
        Args:
            component_name: Name of the security component
            ttl: Time-to-live in seconds
        """
        self._component_ttls[component_name] = ttl
        logger.info(f"Optimized cache TTL for {component_name}: {ttl}s")

class ParallelProcessor:
    """
    Parallel processing utility for security components.
    Enables concurrent execution of multiple filters and detectors.
    """
    
    def __init__(self, max_workers: int = 4):
        """
        Initialize the parallel processor.
        
        Args:
            max_workers: Maximum number of worker threads
        """
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def process_components_parallel(self, 
                                   components: List[Any], 
                                   input_data: Any,
                                   method_name: str = 'filter') -> List[Tuple[Any, Any]]:
        """
        Process multiple security components in parallel.
        
        Args:
            components: List of security components to process
            input_data: Input data to process
            method_name: Method name to call on each component
            
        Returns:
            List of (component, result) tuples
        """
        def process_component(component):
            try:
                method = getattr(component, method_name)
                result = method(input_data)
                return (component, result)
            except Exception as e:
                logger.error(f"Error processing component {component.__class__.__name__}: {e}")
                return (component, None)
        
        # Submit all tasks
        future_to_component = {
            self.executor.submit(process_component, comp): comp 
            for comp in components
        }
        
        # Collect results
        results = []
        for future in as_completed(future_to_component):
            component, result = future.result()
            results.append((component, result))
        
        return results
    
    def shutdown(self):
        """Shutdown the executor."""
        self.executor.shutdown(wait=True)

# Global cache instance
_global_cache = IntelligentCache()

def get_cache() -> IntelligentCache:
    """Get the global cache instance."""
    return _global_cache

def cached_component_call(component_name: str, cache_key_data: Any = None):
    """
    Decorator to cache component method calls.
    
    Args:
        component_name: Name of the component for cache key generation
        cache_key_data: Additional data to include in cache key
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Generate cache key from arguments
            if cache_key_data is not None:
                key_data = cache_key_data
            elif len(args) > 1:
                key_data = args[1]  # Skip 'self' argument
            elif 'input_data' in kwargs:
                key_data = kwargs.get('input_data', '')
            else:
                key_data = str(args) + str(kwargs)
            
            # Try to get from cache
            cached_result = get_cache().get_component(component_name, key_data, **kwargs)
            if cached_result is not None:
                return cached_result
            
            # Execute the function
            result = func(*args, **kwargs)
            
            # Cache the result
            get_cache().set_component(component_name, key_data, result, **kwargs)
            
            return result
        return wrapper
    return decorator 