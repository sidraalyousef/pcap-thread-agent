"""HTTP API wrapping the pcap analysis pipeline for a frontend (e.g. a Lovable app) to call.

tshark must be available on whatever machine runs this server -- the frontend never touches
it directly. No external API or key is required; narratives are generated locally.
"""
import os
import tempfile

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from .detectors import run_all_detectors
from .flows import build_flows
from .models import Thread
from .narrative import generate_narratives
from .report import generate_markdown_report
from .tshark_runner import extract_packets, find_tshark

MAX_UPLOAD_BYTES = int(os.environ.get("PCAP_AGENT_MAX_UPLOAD_BYTES", 200 * 1024 * 1024))

app = FastAPI(title="pcap-thread-agent")

_allowed_origins = os.environ.get("API_ALLOWED_ORIGINS", "https://pcap-guardian.lovable.app")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _allowed_origins.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)


def _json_safe(value):
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return value


def _serialize_thread(thread: Thread) -> dict:
    return {
        "id": thread.id,
        "type": thread.type,
        "severity": thread.severity,
        "actor": thread.actor,
        "targets": thread.targets,
        "start_time": thread.start_time,
        "end_time": thread.end_time,
        "evidence": _json_safe(thread.evidence),
        "narrative": thread.narrative,
    }


async def _save_upload_to_temp(file: UploadFile) -> str:
    suffix = os.path.splitext(file.filename or "")[1] or ".pcap"
    fd, path = tempfile.mkstemp(suffix=suffix)
    total = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail=f"File exceeds {MAX_UPLOAD_BYTES}-byte limit")
                out.write(chunk)
    except Exception:
        os.unlink(path)
        raise
    return path


@app.get("/health")
def health():
    try:
        tshark_path = find_tshark()
    except FileNotFoundError as e:
        return {"status": "degraded", "tshark": str(e)}
    return {"status": "ok", "tshark": tshark_path}


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    format: str = Query("json", pattern="^(json|markdown)$"),
):
    path = await _save_upload_to_temp(file)
    try:
        try:
            packets = extract_packets(path)
            flows = list(build_flows(packets).values())
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="tshark not found on the server")
        except RuntimeError as e:
            raise HTTPException(status_code=422, detail=f"Failed to parse capture: {e}")

        threads = run_all_detectors(flows)

        if threads:
            generate_narratives(threads)

        if format == "markdown":
            return PlainTextResponse(generate_markdown_report(threads, source_file=file.filename or "capture"))

        return {
            "source_file": file.filename,
            "thread_count": len(threads),
            "threads": [_serialize_thread(t) for t in threads],
        }
    finally:
        os.unlink(path)
