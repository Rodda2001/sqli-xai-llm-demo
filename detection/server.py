"""
FileSense — Detection Server (Improved)
========================================
FastAPI server wrapping the ML + SHAP + LLM detection pipeline.
Robust error handling, input validation, never exposes stack traces.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional
import uvicorn
import sys
import os
import time
import traceback

sys.path.insert(0, os.path.dirname(__file__))

from config import MAX_QUERY_LENGTH, LOG_LEVEL
from logger import get_logger

log = get_logger("server")

# ── Import detection engine (logs model loading) ──────
try:
    from detect import detect
    MODELS_LOADED = True
except Exception as e:
    log.error(f"Failed to load detection engine: {e}")
    MODELS_LOADED = False
    detect = None


app = FastAPI(
    title       = "Detection Server",
    description = "ML + SHAP + LLM SQL Injection Detection",
    version     = "3.1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)


# ── Global exception handler — never expose stack traces ──────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error(f"Unhandled error on {request.url.path}: {exc}")
    log.error(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": "An unexpected error occurred."},
    )


# ── Request model ─────────────────────────────────────
class QueryRequest(BaseModel):
    query:       str = Field(..., min_length=0, max_length=MAX_QUERY_LENGTH + 100)
    source_ip:   Optional[str] = "unknown"
    source_host: Optional[str] = "unknown"


# ── Health check ──────────────────────────────────────
@app.get("/health")
def health():
    if not MODELS_LOADED:
        return {
            "status":  "unhealthy",
            "service": "FileSense Detection",
            "models":  "failed",
            "error":   "Models failed to load at startup",
        }
    try:
        test = detect("SELECT 1")
        return {
            "status":  "healthy",
            "service": "FileSense Detection",
            "models":  "loaded",
            "test":    "passed",
        }
    except Exception as e:
        log.error(f"Health check failed: {e}")
        return {
            "status":  "unhealthy",
            "service": "FileSense Detection",
            "models":  "loaded",
            "error":   "Detection test failed",
        }


# ── Status endpoint ───────────────────────────────────
@app.get("/status")
def status():
    if MODELS_LOADED:
        from detect import model1, model2, vectorizer1, vectorizer2
        return {
            "status":  "online",
            "model1":  "loaded" if model1 is not None else "failed",
            "model2":  "loaded" if model2 is not None else "failed",
            "version": "3.1",
        }
    return {
        "status":  "degraded",
        "model1":  "failed",
        "model2":  "failed",
        "version": "3.1",
    }


# ── Detection endpoint ────────────────────────────────
@app.post("/detect")
def run_detection(req: QueryRequest):
    if not MODELS_LOADED:
        raise HTTPException(status_code=503, detail="Models not loaded")

    # Validate input
    query = (req.query or "").strip()
    if not query:
        return {
            "query":           "",
            "timestamp":       "",
            "is_sqli":         False,
            "confidence":      0.0,
            "label":           "Normal",
            "attack_type":     "normal",
            "severity":        "none",
            "mitre":           None,
            "xai_tokens":      [],
            "llm_explanation": None,
            "source_ip":       req.source_ip,
            "source_host":     req.source_host,
        }

    if len(query) > MAX_QUERY_LENGTH:
        query = query[:MAX_QUERY_LENGTH]
        log.warning(f"Query truncated to {MAX_QUERY_LENGTH} chars")

    try:
        start = time.time()
        result = detect(query)
        elapsed = time.time() - start

        # Add source info
        result["source_ip"]   = req.source_ip
        result["source_host"] = req.source_host

        log.info(f"Detection completed in {elapsed:.3f}s — sqli={result['is_sqli']} conf={result['confidence']}")
        return result

    except Exception as e:
        log.error(f"Detection error: {e}")
        log.error(traceback.format_exc())
        # Return safe fallback instead of crashing
        return {
            "query":           query,
            "timestamp":       "",
            "is_sqli":         False,
            "confidence":      0.0,
            "label":           "Normal",
            "attack_type":     "normal",
            "severity":        "none",
            "mitre":           None,
            "xai_tokens":      [],
            "llm_explanation": None,
            "source_ip":       req.source_ip,
            "source_host":     req.source_host,
        }


# ── Start server ──────────────────────────────────────
if __name__ == "__main__":
    print("\n FileSense Detection Server starting...")
    print(" http://localhost:8000\n")
    uvicorn.run(
        "server:app",
        host    = "0.0.0.0",
        port    = 8000,
        reload  = False,
    )
