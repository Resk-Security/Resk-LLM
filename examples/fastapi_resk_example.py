"""
FastAPI example: Integrating RESK-LLM cache, monitoring, and advanced security.
"""
from fastapi import FastAPI, Request, HTTPException
from resk_llm.core.cache import get_cache
from resk_llm.core.monitoring import log_security_event, EventType, Severity
from resk_llm.core.advanced_security import AdaptiveSecurityManager
from resk_llm.heuristic_filter import HeuristicFilter

# Utiliser l'instance globale du cache
cache = get_cache()
# MonitoringManager n'existe pas, utiliser log_security_event directement
security = AdaptiveSecurityManager(config={"anomaly_sensitivity": 0.7})
heuristic_filter = HeuristicFilter()  # Pas d'argument cache ni monitoring

app = FastAPI()

@app.post("/secure-llm")
async def secure_llm_endpoint(request: Request):
    data = await request.json()
    user_input = data.get("prompt", "")

    # 1. Heuristic filtering
    passed, reason, filtered = heuristic_filter.filter(user_input)
    if not passed:
        log_security_event(
            EventType.SECURITY_BLOCK,
            "HeuristicFilter",
            f"Input blocked: {reason}",
            Severity.HIGH,
            details={"input": user_input}
        )
        raise HTTPException(status_code=400, detail=f"Input blocked: {reason}")

    # 2. Advanced security analysis (anomaly, risk)
    risk = security.anomaly_detector.get_user_risk_assessment(user_id="anonymous")
    if risk["risk_level"] in ["high", "critical"]:
        log_security_event(
            EventType.ANOMALOUS_BEHAVIOR,
            "AdaptiveSecurityManager",
            f"High risk detected: {risk['risk_level']}",
            Severity.CRITICAL,
            details={"risk": risk, "input": user_input}
        )
        raise HTTPException(status_code=403, detail=f"High risk detected: {risk['risk_level']}")

    # 3. Caching (optional)
    cached = cache.get("LLMResponse", user_input)
    if cached:
        log_security_event(
            EventType.CACHE_HIT,
            "IntelligentCache",
            "Cache hit",
            Severity.LOW,
            details={"input": user_input}
        )
        return {"result": cached, "cached": True}

    # 4. Call your LLM or process
    result = f"Simulated response for: {filtered}"

    # 5. Cache and monitoring
    cache.set("LLMResponse", user_input, result)
    log_security_event(
        EventType.LLM_API_CALL,
        "LLM",
        "LLM call processed",
        Severity.LOW,
        details={"input": user_input, "result": result}
    )

    return {"result": result, "risk": risk, "cached": False} 