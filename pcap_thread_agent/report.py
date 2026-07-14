"""Renders detected threads into a Markdown report."""
import datetime
from typing import List

from .models import Thread

SEVERITY_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def _fmt_time(epoch: float) -> str:
    return datetime.datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S UTC")


def generate_markdown_report(threads: List[Thread], source_file: str) -> str:
    lines = [f"# Threat Report: `{source_file}`", ""]

    if not threads:
        lines.append("No threats were flagged by the heuristics.")
        return "\n".join(lines)

    lines.append(f"{len(threads)} threat(s) flagged.\n")

    for thread in threads:
        lines.append(f"## [{SEVERITY_LABEL.get(thread.severity, thread.severity.upper())}] {thread.type} — {thread.id}")
        lines.append("")
        lines.append(f"- **Actor:** {thread.actor}")
        lines.append(f"- **Targets:** {', '.join(thread.targets)}")
        lines.append(f"- **Window:** {_fmt_time(thread.start_time)} → {_fmt_time(thread.end_time)}")
        lines.append("- **Evidence:**")
        for key, value in thread.evidence.items():
            lines.append(f"  - {key}: {value}")
        lines.append("")
        if thread.narrative:
            lines.append("**Threat summary:**")
            lines.append("")
            lines.append(thread.narrative)
        lines.append("")

    return "\n".join(lines)
