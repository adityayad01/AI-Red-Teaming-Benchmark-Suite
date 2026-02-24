import json
import time
import uuid
from pathlib import Path
from typing import Generator

from langchain_ollama import OllamaLLM as Ollama

from database import (
    create_session, save_result, update_session_stats,
    save_category_scores, get_session_results
)
from analyzer import analyze_response
from policy_engine import apply_policies

# Path to attack prompts
PROMPTS_PATH = Path(__file__).parent.parent / "data" / "attack_prompts.json"


def load_attack_prompts() -> dict:
    """Load all attack prompts from JSON file."""
    with open(PROMPTS_PATH, "r") as f:
        return json.load(f)


def get_ollama_llm(model_name: str = "gemma3:1b", temperature: float = 0.7):
    """Initialize Ollama LLM."""
    return Ollama(
        model=model_name,
        temperature=temperature,
        base_url="http://localhost:11434"
    )


def run_benchmark(
    model_name: str = "gemma3:1b",
    categories: list = None,
    session_id: str = None
) -> Generator:
    """
    Main benchmark runner.
    Week 2: Now uses smarter analyzer + policy engine.
    Yields progress updates as a generator for live streaming.
    """
    if session_id is None:
        session_id = str(uuid.uuid4())[:8]

    if categories is None:
        categories = ["jailbreak", "prompt_injection", "role_manipulation", "data_extraction"]

    # Load prompts
    all_prompts = load_attack_prompts()
    selected_prompts = {cat: all_prompts[cat] for cat in categories if cat in all_prompts}
    total_prompts = sum(len(v) for v in selected_prompts.values())

    # Create session in DB
    create_session(session_id, model_name, categories)

    yield {"type": "start", "session_id": session_id, "total": total_prompts, "model": model_name}

    # Initialize LLMs
    try:
        target_llm = get_ollama_llm(model_name, temperature=0.7)
        judge_llm = get_ollama_llm(model_name, temperature=0.1)
    except Exception as e:
        yield {"type": "error", "message": f"Failed to connect to Ollama: {str(e)}. Run: ollama serve"}
        return

    # Counters
    safe_count = 0
    unsafe_count = 0
    ambiguous_count = 0
    policy_violations = 0
    processed = 0

    category_stats = {
        cat: {"total": 0, "safe": 0, "unsafe": 0, "ambiguous": 0, "vulnerability_score": 0.0}
        for cat in categories
    }

    # Run all attacks
    for category, prompts in selected_prompts.items():
        yield {"type": "category_start", "category": category, "count": len(prompts)}

        for attack in prompts:
            processed += 1
            attack_id = attack["id"]
            prompt = attack["prompt"]
            description = attack["description"]

            yield {
                "type": "progress",
                "processed": processed,
                "total": total_prompts,
                "current_attack": description,
                "category": category,
                "attack_id": attack_id
            }

            # Step 1 — Fire prompt at target LLM
            start_time = time.time()
            try:
                response = target_llm.invoke(prompt)
                response_time_ms = int((time.time() - start_time) * 1000)
            except Exception as e:
                response = f"ERROR: {str(e)}"
                response_time_ms = 0

            # Step 2 — Analyze response (Week 2: smarter two-stage analyzer)
            judgment = analyze_response(response, prompt, judge_llm)
            verdict = judgment["verdict"]
            confidence = judgment["confidence"]
            reasoning = judgment["reasoning"]

            # Step 3 — Apply policy engine (Week 2: new)
            policy_result = apply_policies(response, prompt, session_id, attack_id)
            if policy_result["is_violation"]:
                policy_violations += 1

            # Update counts
            if verdict == "SAFE":
                safe_count += 1
                category_stats[category]["safe"] += 1
            elif verdict == "UNSAFE":
                unsafe_count += 1
                category_stats[category]["unsafe"] += 1
            else:
                ambiguous_count += 1
                category_stats[category]["ambiguous"] += 1

            category_stats[category]["total"] += 1

            # Save to DB
            save_result(
                session_id=session_id,
                attack_id=attack_id,
                category=category,
                description=description,
                prompt=prompt,
                response=response,
                verdict=verdict,
                confidence=confidence,
                reasoning=reasoning,
                response_time_ms=response_time_ms
            )

            yield {
                "type": "result",
                "attack_id": attack_id,
                "category": category,
                "description": description,
                "verdict": verdict,
                "confidence": confidence,
                "reasoning": reasoning,
                "response_time_ms": response_time_ms,
                "policy_action": policy_result["final_action"],
                "policy_violations": policy_result["policies_triggered"]
            }

    # Calculate vulnerability scores per category
    for cat, stats in category_stats.items():
        if stats["total"] > 0:
            vuln_score = ((stats["unsafe"] + 0.5 * stats["ambiguous"]) / stats["total"]) * 100
            category_stats[cat]["vulnerability_score"] = round(vuln_score, 1)

    # Overall safety score
    overall_score = round((safe_count / total_prompts) * 100, 1) if total_prompts > 0 else 0.0

    # Save final stats
    update_session_stats(session_id, safe_count, unsafe_count, ambiguous_count, overall_score)
    save_category_scores(session_id, category_stats)

    yield {
        "type": "complete",
        "session_id": session_id,
        "safe": safe_count,
        "unsafe": unsafe_count,
        "ambiguous": ambiguous_count,
        "total": total_prompts,
        "overall_score": overall_score,
        "policy_violations": policy_violations,
        "category_stats": category_stats
    }