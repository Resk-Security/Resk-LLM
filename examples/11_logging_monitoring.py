# TIP: To avoid loading torch and vector DB features, set enable_heuristic_filter=False and do not provide an embedding_function to PromptSecurityManager.
# Example: Logging and monitoring configuration
import logging
from resk_llm.core.monitoring import get_monitor, log_security_event, EventType, Severity

# Configure logging to a file
logging.basicConfig(filename='resk_security.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# Log a security event
log_security_event(EventType.INJECTION_ATTEMPT, "LoggingExample", "Prompt injection attempt detected", Severity.HIGH)

# Get the monitoring summary
monitor = get_monitor()
summary = monitor.get_security_summary()

# Print the summary
print("Security monitoring summary:")
for key, value in summary.items():
    print(f"  {key}: {value}") 