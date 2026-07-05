"""Turns a detector's structured evidence into a narrative summary via Claude."""
import json
import os

from .models import Thread

MODEL = "claude-sonnet-5"

_SYSTEM_PROMPT = (
    "You are a network security analyst assistant. You are given structured evidence "
    "that a heuristic detector extracted from a packet capture, describing one "
    "suspicious sequence of network activity. Write a concise analyst-facing summary. "
    "Base every claim strictly on the evidence given -- do not invent hosts, ports, "
    "timestamps, or techniques that aren't in the evidence. If the evidence is "
    "ambiguous or could be benign, say so plainly instead of overstating confidence."
)


def _build_prompt(thread: Thread) -> str:
    payload = {
        "detector_type": thread.type,
        "heuristic_severity": thread.severity,
        "actor": thread.actor,
        "targets": thread.targets,
        "start_time": thread.start_time,
        "end_time": thread.end_time,
        "duration_seconds": round(thread.end_time - thread.start_time, 2),
        "evidence": thread.evidence,
    }
    return (
        "Detector evidence (JSON):\n"
        f"{json.dumps(payload, indent=2, default=str)}\n\n"
        "Write:\n"
        "1. A 1-2 sentence plain-language summary of what happened.\n"
        "2. A likely technique or MITRE ATT&CK technique ID, if the evidence supports one "
        "(otherwise say 'not enough evidence to map to a technique').\n"
        "3. A one-line severity justification.\n"
        "4. A single recommended next step for the analyst.\n"
        "Keep the whole response under 120 words."
    )


def summarize_thread(thread: Thread) -> str:
    from anthropic import Anthropic  # imported lazily so --no-llm runs don't need the package

    client = Anthropic()
    response = client.messages.create(
        model=MODEL,
        max_tokens=400,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _build_prompt(thread)}],
    )
    return response.content[0].text.strip()


def summarize_threads(threads: list[Thread]) -> None:
    """Populates thread.narrative in place; raises if ANTHROPIC_API_KEY is missing."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Export it before running, or pass --no-llm "
            "to generate a report with heuristic evidence only."
        )
    for thread in threads:
        thread.narrative = summarize_thread(thread)
