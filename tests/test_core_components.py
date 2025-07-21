"""
Tests for core components of RESK-LLM.
"""

import pytest
from unittest.mock import Mock, patch
import tempfile
import os

from resk_llm.core.abc import ConcreteSecurityComponent, FilterBase, DetectorBase
from resk_llm.core.cache import IntelligentCache, get_cache, cached_component_call
from resk_llm.core.monitoring import (
    ReskMonitor, SecurityEvent, EventType, Severity, 
    get_monitor, log_security_event
)
from resk_llm.core.advanced_security import (
    AdvancedCrypto, AnomalyDetector, AdaptiveSecurityManager,
    ThreatLevel, get_security_manager
)
from resk_llm.core.canary_tokens import CanaryTokenManager, CanaryTokenDetector


class TestSecurityComponent:
    """Test the base SecurityComponent class."""
    
    def test_security_component_initialization(self):
        """Test SecurityComponent initialization."""
        component = ConcreteSecurityComponent(name="test", enabled=True)
        assert component.name == "test"
        assert component.enabled is True
    
    def test_security_component_disable(self):
        """Test disabling a security component."""
        component = ConcreteSecurityComponent(name="test", enabled=True)
        component.disable()
        assert component.enabled is False
    
    def test_security_component_enable(self):
        """Test enabling a security component."""
        component = ConcreteSecurityComponent(name="test", enabled=False)
        component.enable()
        assert component.enabled is True


class TestIntelligentCache:
    """Test the IntelligentCache class."""
    
    def test_cache_initialization(self):
        """Test cache initialization."""
        cache = IntelligentCache(max_size=100)
        assert cache.max_size == 100
        assert len(cache) == 0
    
    def test_cache_set_get(self):
        """Test setting and getting values from cache."""
        cache = IntelligentCache(max_size=10)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
    
    def test_cache_miss(self):
        """Test cache miss behavior."""
        cache = IntelligentCache(max_size=10)
        assert cache.get("nonexistent") is None
        assert cache.get("nonexistent", "default") == "default"
    
    def test_cache_eviction(self):
        """Test cache eviction when full."""
        cache = IntelligentCache(max_size=2)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")  # Should evict key1
        
        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"
    
    def test_cache_delete(self):
        """Test cache deletion."""
        cache = IntelligentCache(max_size=10)
        cache.set("key1", "value1")
        cache.delete("key1")
        assert cache.get("key1") is None
    
    def test_cache_clear(self):
        """Test cache clearing."""
        cache = IntelligentCache(max_size=10)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()
        assert len(cache) == 0


class TestReskMonitor:
    """Test the ReskMonitor class."""
    
    def test_monitor_initialization(self):
        """Test monitor initialization."""
        monitor = ReskMonitor()
        assert monitor is not None
        assert hasattr(monitor, 'log_event')
    
    def test_log_security_event(self):
        """Test logging security events."""
        monitor = ReskMonitor()
        event = SecurityEvent(
                event_type=EventType.SECURITY_VIOLATION,
                severity=Severity.HIGH,
            timestamp=1234567890.0,
            component_name="TestComponent",
            message="Test security violation"
            )
        monitor.log_event(event)
        events = monitor.get_events()
        assert len(events) > 0
        assert events[0].event_type == EventType.SECURITY_VIOLATION
    
    def test_security_event_creation(self):
        """Test security event creation."""
        event = SecurityEvent(
            event_type=EventType.SECURITY_VIOLATION,
            severity=Severity.HIGH,
            timestamp=1234567890.0,
            component_name="TestComponent",
            message="Test security violation"
        )
        assert event.event_type == EventType.SECURITY_VIOLATION
        assert event.severity == Severity.HIGH
        assert event.component_name == "TestComponent"


class TestAdvancedCrypto:
    """Test the AdvancedCrypto class."""
    
    def test_crypto_initialization(self):
        """Test crypto initialization."""
        crypto = AdvancedCrypto()
        assert crypto is not None
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption."""
        crypto = AdvancedCrypto()
        original_text = "Hello, World!"
        encrypted = crypto.encrypt(original_text)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original_text


class TestAnomalyDetector:
    """Test the AnomalyDetector class."""
    
    def test_anomaly_detector_initialization(self):
        """Test anomaly detector initialization."""
        detector = AnomalyDetector()
        assert detector is not None
    
    def test_detect_anomalies(self):
        """Test anomaly detection."""
        detector = AnomalyDetector()
        
        # Train the detector with some data
        training_data = [
            {'user_id': 'user1', 'request_rate': 1.0, 'timestamp': 1234567890.0},
            {'user_id': 'user2', 'request_rate': 2.0, 'timestamp': 1234567891.0}
        ]
        detector.train(training_data)
        
        # Test anomaly detection
        activity = {'user_id': 'user1', 'request_rate': 10.0, 'timestamp': 1234567892.0}
        result = detector.analyze_activity('user1', activity)
        assert 'anomaly_score' in result
        assert 'threat_level' in result


class TestAdaptiveSecurityManager:
    """Test the AdaptiveSecurityManager class."""
    
    def test_security_manager_initialization(self):
        """Test security manager initialization."""
        manager = AdaptiveSecurityManager()
        assert manager is not None
    
    def test_threat_level_assessment(self):
        """Test threat level assessment."""
        manager = AdaptiveSecurityManager()
        request_data = {'content': 'normal request'}
        threat_level = manager.assess_threat_level('user1', request_data)
        assert isinstance(threat_level, ThreatLevel)
    
    def test_adaptive_response(self):
        """Test adaptive response generation."""
        manager = AdaptiveSecurityManager()
        threat_level = ThreatLevel.MEDIUM
        response = manager.generate_adaptive_response(threat_level, 'user1')
        assert isinstance(response, dict)
        assert 'allowed' in response


class TestCanaryTokenManager:
    """Test the CanaryTokenManager class."""
    
    def test_canary_token_creation(self):
        """Test canary token creation."""
        manager = CanaryTokenManager()
        token = manager.create_token({'context': 'test'})
        assert token is not None
        assert len(token) > 0
    
    def test_canary_token_detection(self):
        """Test canary token detection."""
        manager = CanaryTokenManager()
        token = manager.create_token({'context': 'test'})
        
        # Insert token into text
        text_with_token = f"This is a test message with {token} embedded"
        tokens_found, leaked_tokens = manager.check_for_leaks(text_with_token)
        
        assert tokens_found
        assert len(leaked_tokens) > 0
    
    def test_canary_token_not_detected(self):
        """Test that normal text doesn't trigger canary detection."""
        manager = CanaryTokenManager()
        normal_text = "This is a normal message without any tokens"
        tokens_found, leaked_tokens = manager.check_for_leaks(normal_text)
        
        assert not tokens_found
        assert len(leaked_tokens) == 0


class TestCachedComponentCall:
    """Test the cached_component_call decorator."""
    
    def test_cached_component_call(self):
        """Test that the decorator returns a callable function."""
        def test_function(data):
            return f"processed_{data}"
        
        decorated = cached_component_call("TestComponent")(test_function)
        assert callable(decorated)
        
        # Test that the decorated function works
        result = decorated("test_data")
        assert result == "processed_test_data"


class TestGetFunctions:
    """Test the get_* functions."""
    
    def test_get_cache(self):
        """Test get_cache function."""
        cache = get_cache()
        assert isinstance(cache, IntelligentCache)
    
    def test_get_monitor(self):
        """Test get_monitor function."""
        monitor = get_monitor()
        assert isinstance(monitor, ReskMonitor)
    
    def test_get_security_manager(self):
        """Test get_security_manager function."""
        manager = get_security_manager()
        assert isinstance(manager, AdaptiveSecurityManager) 