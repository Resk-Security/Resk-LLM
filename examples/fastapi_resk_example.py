"""
FastAPI example: Secure an endpoint using the RESK orchestrator
"""
from fastapi import FastAPI, Request, HTTPException
from resk_llm.RESK import RESK

app = FastAPI()
resk = RESK()

@app.post("/secure-llm")
async def secure_llm_endpoint(request: Request):
    data = await request.json()
    user_input = data.get("prompt", "")
    # Process the prompt through all security layers
    result = resk.process_prompt(user_input)
    # If the result is blocked, return an error
    if "[BLOCKED]" in result:
        raise HTTPException(status_code=400, detail="Input blocked by security policy.")
    # Otherwise, return the secured result
    return {"result": result} 