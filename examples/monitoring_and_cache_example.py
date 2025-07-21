# Monitoring, cache, and advanced security example
from resk_llm.core.monitoring import get_monitor, log_security_event, EventType, Severity
from resk_llm.core.cache import get_cache
from resk_llm.core.advanced_security import get_security_manager

# Get the monitoring, cache, and security manager instances
monitor = get_monitor()
cache = get_cache()
security_manager = get_security_manager()

# Log a security event
log_security_event(EventType.INJECTION_ATTEMPT, "Demo", "Prompt injection attempt detected", Severity.HIGH)

# Get the monitoring dashboard
dashboard = monitor.get_security_summary()
print("Security dashboard:", dashboard)

# Use the cache
cache.set("demo_key", "demo_value")
print("Cache demo_key:", cache.get("demo_key"))

# User risk assessment
risk = security_manager.anomaly_detector.get_user_risk_assessment(user_id="user42")
print("User risk assessment:", risk) 