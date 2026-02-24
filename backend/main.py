import json
import uuid
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from attack_engine import run_benchmark, load_attack_prompts
from database import (
    get_all_sessions, get_session_results,
    get_session_category_scores, get_session_by_id, init_db
)

# Initialize FastAPI app
app = FastAPI(
    title="AI Red Teaming Benchmark Suite",
    description="Automated LLM vulnerability testing tool",
    version="1.0.0"
)

# Allow Streamlit frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database on startup
init_db()


# ─────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────

class BenchmarkRequest(BaseModel):
    model_name: str = "gemma3:1b"
    categories: List[str] = ["jailbreak", "prompt_injection", "role_manipulation", "data_extraction"]
    session_id: Optional[str] = None


class SingleTestRequest(BaseModel):
    model_name: str = "mistral"
    prompt: str
    category: str = "custom"


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "message": "AI Red Teaming Benchmark Suite API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
def health_check():
    """Check if API and Ollama are reachable."""
    try:
        from langchain_ollama import OllamaLLM
        llm = OllamaLLM(model="gemma3:1b", base_url="http://localhost:11434")
        llm.invoke("say hi in 3 words")
        ollama_status = "connected"
    except Exception as e:
        ollama_status = f"error: {str(e)}"

    return {
        "api": "running",
        "ollama": ollama_status
    }


@app.get("/models")
def list_models():
    """Return available Ollama models."""
    import subprocess
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")[1:]  # Skip header
        models = [line.split()[0] for line in lines if line.strip()]
        return {"models": models}
    except Exception as e:
        return {"models": ["gemma3:1b"], "note": f"Could not fetch live models: {str(e)}"}


@app.get("/attack-categories")
def get_attack_categories():
    """Return all available attack categories and their prompt counts."""
    prompts = load_attack_prompts()
    return {
        cat: {
            "count": len(items),
            "description": get_category_description(cat)
        }
        for cat, items in prompts.items()
    }


@app.post("/benchmark/start")
def start_benchmark(request: BenchmarkRequest):
    """
    Start a new benchmark run.
    Returns a session_id to track progress via /benchmark/stream/{session_id}
    """
    session_id = request.session_id or str(uuid.uuid4())[:8]

    # Validate categories
    valid_categories = ["jailbreak", "prompt_injection", "role_manipulation", "data_extraction"]
    invalid = [c for c in request.categories if c not in valid_categories]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid categories: {invalid}")

    return {
        "session_id": session_id,
        "model": request.model_name,
        "categories": request.categories,
        "stream_url": f"/benchmark/stream/{session_id}",
        "message": "Benchmark started. Connect to stream_url for live results."
    }


@app.get("/benchmark/stream/{session_id}")
def stream_benchmark(
    session_id: str,
    model_name: str = "mistral",
    categories: str = "jailbreak,prompt_injection,role_manipulation,data_extraction"
):
    """
    Stream benchmark results as Server-Sent Events (SSE).
    Frontend can listen to this endpoint for live progress.
    """
    category_list = [c.strip() for c in categories.split(",")]

    def generate():
        for event in run_benchmark(model_name, category_list, session_id):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/sessions")
def list_sessions():
    """Return all past benchmark sessions."""
    return {"sessions": get_all_sessions()}


@app.get("/sessions/{session_id}")
def get_session(session_id: str):
    """Return details of a specific session."""
    session = get_session_by_id(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.get("/sessions/{session_id}/results")
def get_results(session_id: str):
    """Return all results for a specific session."""
    results = get_session_results(session_id)
    return {"session_id": session_id, "results": results}


@app.get("/sessions/{session_id}/scores")
def get_scores(session_id: str):
    """Return category vulnerability scores for a session."""
    session = get_session_by_id(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    scores = get_session_category_scores(session_id)
    return {
        "session_id": session_id,
        "overall_score": session["overall_score"],
        "category_scores": scores
    }


@app.get("/sessions/{session_id}/results/unsafe")
def get_unsafe_results(session_id: str):
    """Return only unsafe results for a session - useful for reports."""
    results = get_session_results(session_id)
    unsafe = [r for r in results if r["verdict"] == "UNSAFE"]
    return {"session_id": session_id, "unsafe_count": len(unsafe), "results": unsafe}


# ─────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────

def get_category_description(category: str) -> str:
    descriptions = {
        "jailbreak": "Attempts to make the model ignore its safety guidelines and restrictions",
        "prompt_injection": "Injects malicious instructions into seemingly normal tasks",
        "role_manipulation": "Tricks the model into adopting a harmful or unrestricted persona",
        "data_extraction": "Attempts to extract sensitive system information, prompts, or credentials"
    }
    return descriptions.get(category, "Custom attack category")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

# ─────────────────────────────────────────────
# Policy Engine Routes (Week 2)
# ─────────────────────────────────────────────

@app.get("/sessions/{session_id}/policy")
def get_policy_report(session_id: str):
    """Return policy violation summary for a session."""
    from policy_engine import get_policy_summary
    return get_policy_summary(session_id)


@app.get("/sessions/{session_id}/audit")
def get_audit_log_route(session_id: str):
    """Return full audit log for a session."""
    from policy_engine import get_audit_log
    return {"session_id": session_id, "audit_log": get_audit_log(session_id)}


@app.get("/sessions/{session_id}/scores/detailed")
def get_detailed_scores(session_id: str):
    """Return detailed scoring with risk levels (Week 2)."""
    from scorer import calculate_scores, generate_executive_summary
    results = get_session_results(session_id)
    if not results:
        raise HTTPException(status_code=404, detail="No results found for session")
    scores = calculate_scores(results)
    summary = generate_executive_summary(scores)
    return {"session_id": session_id, "scores": scores, "executive_summary": summary}


# ─────────────────────────────────────────────
# Report Generation Route (Week 3)
# ─────────────────────────────────────────────

@app.get("/sessions/{session_id}/report")
def generate_report(session_id: str):
    """Generate and return a PDF report for a session."""
    from fastapi.responses import FileResponse
    from report import generate_pdf_report
    from scorer import calculate_scores, generate_executive_summary
    from policy_engine import get_policy_summary

    session = get_session_by_id(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    results = get_session_results(session_id)
    if not results:
        raise HTTPException(status_code=404, detail="No results found for session")

    scores = calculate_scores(results)
    policy_summary = get_policy_summary(session_id)

    pdf_path = generate_pdf_report(
        session_id=session_id,
        session_data=session,
        results=results,
        scores=scores,
        policy_summary=policy_summary
    )

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"redteam_report_{session_id}.pdf"
    )