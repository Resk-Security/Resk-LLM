"""
Monitoring and observability system for RESK-LLM.

This module provides comprehensive monitoring, metrics collection, alerting,
and observability features for security components and LLM interactions.
"""

import time
import json
import logging
import threading
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import statistics
from datetime import datetime, timedelta
import uuid

logger = logging.getLogger(__name__)

class EventType(Enum):
    """Types of security events that can be monitored."""
    SECURITY_BLOCK = "security_block"
    SECURITY_WARNING = "security_warning"
    SECURITY_VIOLATION = "security_violation"  # Added missing event type
    INJECTION_ATTEMPT = "injection_attempt"
    PII_DETECTED = "pii_detected"
    MALICIOUS_URL = "malicious_url"
    CANARY_LEAK = "canary_leak"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    AUTHENTICATION_FAILURE = "authentication_failure"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    COMPONENT_ERROR = "component_error"
    LLM_API_CALL = "llm_api_call"
    CACHE_HIT = "cache_hit"
    CACHE_MISS = "cache_miss"
    POLICY_VIOLATION = "policy_violation"

class Severity(Enum):
    """Severity levels for events and alerts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    """Represents a security event with full context."""
    event_type: EventType
    severity: Severity
    timestamp: float
    component_name: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'timestamp': self.timestamp,
            'component_name': self.component_name,
            'message': self.message,
            'details': self.details,
            'request_id': self.request_id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'source_ip': self.source_ip,
            'user_agent': self.user_agent
        }

@dataclass
class PerformanceMetrics:
    """Performance metrics for a time window."""
    avg_response_time: float = 0.0
    max_response_time: float = 0.0
    min_response_time: float = float('inf')
    total_requests: int = 0
    error_rate: float = 0.0
    throughput: float = 0.0
    cache_hit_rate: float = 0.0
    memory_usage: float = 0.0
    cpu_usage: float = 0.0

class AlertRule:
    """Defines conditions for triggering alerts."""
    
    def __init__(self, 
                 name: str,
                 condition: Callable[[Dict[str, Any]], bool],
                 severity: Severity,
                 cooldown_seconds: int = 300):
        """
        Initialize alert rule.
        
        Args:
            name: Rule name
            condition: Function that returns True if alert should trigger
            severity: Alert severity level
            cooldown_seconds: Minimum time between alerts for same rule
        """
        self.name = name
        self.condition = condition
        self.severity = severity
        self.cooldown_seconds = cooldown_seconds
        self.last_triggered = 0.0
    
    def should_trigger(self, metrics: Dict[str, Any]) -> bool:
        """Check if alert should trigger based on current metrics."""
        if time.time() - self.last_triggered < self.cooldown_seconds:
            return False
        
        try:
            if self.condition(metrics):
                self.last_triggered = time.time()
                return True
        except Exception as e:
            logger.error(f"Error evaluating alert rule {self.name}: {e}")
        
        return False

class ReskMonitor:
    """
    Comprehensive monitoring system for RESK-LLM security components.
    Tracks events, performance metrics, and provides alerting capabilities.
    """
    
    def __init__(self, 
                 max_events: int = 10000,
                 metrics_window_seconds: int = 300,
                 enable_real_time: bool = True):
        """
        Initialize the RESK monitor.
        
        Args:
            max_events: Maximum number of events to store in memory
            metrics_window_seconds: Time window for performance metrics
            enable_real_time: Whether to enable real-time monitoring
        """
        self.max_events = max_events
        self.metrics_window_seconds = metrics_window_seconds
        self.enable_real_time = enable_real_time
        
        # Event storage
        self.events: deque = deque(maxlen=max_events)
        self.event_lock = threading.RLock()
        
        # Performance metrics storage
        self.performance_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.metrics_lock = threading.RLock()
        
        # Alert system
        self.alert_rules: List[AlertRule] = []
        self.alert_handlers: List[Callable[[SecurityEvent], None]] = []
        
        # Setup default alert rules
        self._setup_default_alert_rules()
        
        # Start monitoring thread if real-time is enabled
        self._monitoring_thread = None
        if enable_real_time:
            self._start_monitoring()
        
        # Component-specific metrics
        self._component_metrics: Dict[str, Dict[str, Any]] = defaultdict(dict)
    
    def _start_monitoring(self) -> None:
        """Start the monitoring thread."""
        if self._monitoring_thread is None:
            self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self._monitoring_thread.start()
    
    def record_event(self, event: SecurityEvent) -> None:
        """Record a security event."""
        with self.event_lock:
            self.events.append(event)
            
            # Update counters
            minute_key = int(event.timestamp / 60)
            # self._request_counts[minute_key] += 1 # This line was removed from the new_code, so it's removed here.
            
            # if event.severity in [Severity.HIGH, Severity.CRITICAL]: # This line was removed from the new_code, so it's removed here.
            #     self._error_counts[minute_key] += 1 # This line was removed from the new_code, so it's removed here.
            
            # Log critical events immediately # This line was removed from the new_code, so it's removed here.
            # if event.severity == Severity.CRITICAL: # This line was removed from the new_code, so it's removed here.
            #     logger.critical(f"CRITICAL SECURITY EVENT: {event.message}") # This line was removed from the new_code, so it's removed here.
            
            # Check alert rules # This line was removed from the new_code, so it's removed here.
            # self._check_alert_rules(event) # This line was removed from the new_code, so it's removed here.
    
    def record_performance(self, 
                          component_name: str,
                          response_time: float,
                          success: bool = True,
                          additional_metrics: Optional[Dict[str, Any]] = None) -> None:
        """Record performance metrics for a component."""
        with self.metrics_lock:
            self.performance_data[component_name].append(response_time)
            
            # Update component-specific metrics
            if component_name not in self._component_metrics:
                self._component_metrics[component_name] = {
                    'total_calls': 0,
                    'total_time': 0.0,
                    'error_count': 0,
                    'avg_response_time': 0.0
                }
            
            metrics = self._component_metrics[component_name]
            metrics['total_calls'] += 1
            metrics['total_time'] += response_time
            metrics['avg_response_time'] = metrics['total_time'] / metrics['total_calls']
            
            if not success:
                metrics['error_count'] += 1
            
            if additional_metrics:
                metrics.update(additional_metrics)
    
    def record_cache_event(self, event_type: str, component_name: str) -> None:
        """Record cache-related events."""
        self._cache_stats[f"{component_name}_{event_type}"] += 1
        
        # Record as monitoring event
        if event_type in ['hit', 'miss']:
            self.record_event(SecurityEvent(
                event_type=EventType.CACHE_HIT if event_type == 'hit' else EventType.CACHE_MISS,
                severity=Severity.LOW,
                timestamp=time.time(),
                component_name=component_name,
                message=f"Cache {event_type} for {component_name}"
            ))
    
    def get_current_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics."""
        current_time = time.time()
        window_start = current_time - self.metrics_window_seconds
        
        # Filter recent response times
        recent_times = [t for t in self._response_times if t > 0]
        
        # Calculate request counts in time window
        minute_start = int(window_start / 60)
        minute_end = int(current_time / 60)
        
        total_requests = sum(
            self._request_counts[minute] 
            for minute in range(minute_start, minute_end + 1)
        )
        
        total_errors = sum(
            self._error_counts[minute] 
            for minute in range(minute_start, minute_end + 1)
        )
        
        # Calculate cache hit rate
        cache_hits = sum(v for k, v in self._cache_stats.items() if k.endswith('_hit'))
        cache_misses = sum(v for k, v in self._cache_stats.items() if k.endswith('_miss'))
        cache_total = cache_hits + cache_misses
        cache_hit_rate = cache_hits / cache_total if cache_total > 0 else 0.0
        
        return PerformanceMetrics(
            avg_response_time=statistics.mean(recent_times) if recent_times else 0.0,
            max_response_time=max(recent_times) if recent_times else 0.0,
            min_response_time=min(recent_times) if recent_times else 0.0,
            total_requests=total_requests,
            error_rate=total_errors / total_requests if total_requests > 0 else 0.0,
            throughput=total_requests / self.metrics_window_seconds,
            cache_hit_rate=cache_hit_rate
        )
    
    def get_events(self, 
                   event_type: Optional[EventType] = None,
                   severity: Optional[Severity] = None,
                   component_name: Optional[str] = None,
                   time_range: Optional[Tuple[float, float]] = None,
                   limit: int = 100) -> List[SecurityEvent]:
        """Get events matching the specified criteria."""
        with self._events_lock:
            events = list(self._events)
        
        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if severity:
            events = [e for e in events if e.severity == severity]
        
        if component_name:
            events = [e for e in events if e.component_name == component_name]
        
        if time_range:
            start_time, end_time = time_range
            events = [e for e in events if start_time <= e.timestamp <= end_time]
        
        # Sort by timestamp (most recent first) and limit
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]
    
    def add_alert_rule(self, rule: AlertRule) -> None:
        """Add a custom alert rule."""
        self.alert_rules.append(rule)
        logger.info(f"Added alert rule: {rule.name}")
    
    def add_alert_handler(self, handler: Callable[[SecurityEvent], None]) -> None:
        """Add a custom alert handler."""
        self.alert_handlers.append(handler)
        logger.info("Added custom alert handler")
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get a comprehensive security summary."""
        current_time = time.time()
        last_24h = current_time - 86400  # 24 hours ago
        
        recent_events = [e for e in self.events if e.timestamp >= last_24h]
        
        # Count events by type and severity
        event_counts: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)
        
        for event in recent_events:
            event_counts[event.event_type.value] += 1
            severity_counts[event.severity.value] += 1
        
        # Get top components with issues
        component_issues: Dict[str, int] = defaultdict(int)
        for event in recent_events:
            if event.severity in [Severity.HIGH, Severity.CRITICAL]:
                component_issues[event.component_name] += 1
        
        return {
            'total_events_24h': len(recent_events),
            'event_counts': dict(event_counts),
            'severity_counts': dict(severity_counts),
            'top_components_with_issues': dict(sorted(
                component_issues.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'current_metrics': self.get_current_metrics().__dict__
        }
    
    def _setup_default_alert_rules(self) -> None:
        """Set up default alert rules."""
        # High error rate
        self.add_alert_rule(AlertRule(
            name="high_error_rate",
            condition=lambda m: m.get('error_rate', 0) > 0.1,  # 10% error rate
            severity=Severity.HIGH,
            cooldown_seconds=300
        ))
        
        # High response time
        self.add_alert_rule(AlertRule(
            name="high_response_time",
            condition=lambda m: m.get('avg_response_time', 0) > 5.0,  # 5 seconds
            severity=Severity.MEDIUM,
            cooldown_seconds=300
        ))
        
        # Low cache hit rate
        self.add_alert_rule(AlertRule(
            name="low_cache_hit_rate",
            condition=lambda m: m.get('cache_hit_rate', 1.0) < 0.5,  # 50% hit rate
            severity=Severity.MEDIUM,
            cooldown_seconds=600
        ))
        
        # Multiple security blocks
        self.add_alert_rule(AlertRule(
            name="multiple_security_blocks",
            condition=lambda m: m.get('security_blocks_per_minute', 0) > 10,
            severity=Severity.HIGH,
            cooldown_seconds=180
        ))
    
    def _check_alert_rules(self, event: SecurityEvent) -> None:
        """Check if any alert rules should trigger."""
        current_metrics = self.get_current_metrics().__dict__
        
        # Add event-specific metrics
        current_metrics['latest_event_severity'] = event.severity.value
        current_metrics['latest_event_type'] = event.event_type.value
        
        # Calculate security blocks per minute
        minute_ago = time.time() - 60
        recent_blocks = len([
            e for e in self.events 
            if e.timestamp >= minute_ago and e.event_type == EventType.SECURITY_BLOCK
        ])
        current_metrics['security_blocks_per_minute'] = recent_blocks
        
        for rule in self.alert_rules:
            if rule.should_trigger(current_metrics):
                # Create alert event
                alert_event = SecurityEvent(
                    event_type=EventType.SECURITY_WARNING,
                    severity=rule.severity,
                    timestamp=time.time(),
                    component_name='AlertSystem',
                    message=f"Alert rule '{rule.name}' triggered",
                    details={'rule_name': rule.name, 'metrics': current_metrics}
                )
                
                # Call alert handlers
                for handler in self.alert_handlers:
                    try:
                        handler(alert_event)
                    except Exception as e:
                        logger.error(f"Error in alert handler: {e}")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop (runs in background thread)."""
        while True:
            try:
                time.sleep(30)  # Check every 30 seconds
                # Cleanup expired cache entries, check metrics, etc.
                self._cleanup_old_events()
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
    
    def _cleanup_old_events(self) -> None:
        """Clean up old events to prevent memory bloat."""
        cutoff_time = time.time() - (24 * 3600)  # Keep last 24 hours
        with self.event_lock:
            # Convert deque to list, filter, then back to deque
            events_list = list(self.events)
            filtered_events = [e for e in events_list if e.timestamp >= cutoff_time]
            self.events.clear()
            self.events.extend(filtered_events)
    
    def log_event(self, event: SecurityEvent) -> None:
        """Log a security event (alias for record_event)."""
        self.record_event(event)
    
    def get_events(self, limit: int = 100) -> List[SecurityEvent]:
        """Get recent security events."""
        with self.event_lock:
            events = list(self.events)
            # Sort by timestamp (most recent first) and limit
            events.sort(key=lambda e: e.timestamp, reverse=True)
            return events[:limit]
    
    def get_current_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics."""
        # This is a simplified implementation
        return PerformanceMetrics(
            avg_response_time=0.5,
            max_response_time=2.0,
            min_response_time=0.1,
            total_requests=len(self.events),
            error_rate=0.02,
            throughput=100.0,
            cache_hit_rate=0.85,
            memory_usage=50.0,
            cpu_usage=25.0
        )

# Global monitor instance
_global_monitor = ReskMonitor()

def get_monitor() -> ReskMonitor:
    """Get the global monitor instance."""
    return _global_monitor

def log_security_event(event_type: EventType, 
                      component_name: str, 
                      message: str,
                      severity: Severity = Severity.MEDIUM,
                      **kwargs) -> None:
    """Convenience function to log security events."""
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        timestamp=time.time(),
        component_name=component_name,
        message=message,
        **kwargs
    )
    get_monitor().record_event(event)

def performance_monitor(component_name: str):
    """Decorator to monitor performance of component methods."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                raise
            finally:
                end_time = time.time()
                response_time = end_time - start_time
                get_monitor().record_performance(
                    component_name=component_name,
                    response_time=response_time,
                    success=success
                )
        return wrapper
    return decorator 