# pcap-thread-agent

Finds and summarizes security threats in a Wireshark capture file — fully local, no external API or key required.

## Pipeline

1. **Extraction** — shells out to `tshark` to pull structured fields per packet (no full-JSON dissection, so it scales to large captures).
2. **Flow reconstruction** — groups packets into 5-tuple conversations with byte/packet/flag stats.
3. **Heuristic detectors** — flag threats: port scans, beaconing, large asymmetric transfers (possible exfil), DNS tunneling signatures, repeated auth failures, and connections to known backdoor-associated ports.
4. **Narrative generation** — each flagged threat's structured evidence is turned into a human-readable summary (plain-language description, likely MITRE ATT&CK technique, severity justification, recommended next step) using local templates — no LLM call, no network dependency.
5. **Report** — a Markdown file with one section per threat.

## Setup

```
pip install -r requirements.txt
```

tshark is auto-detected from PATH, from the default Wireshark install locations on Windows, or from the `PCAP_AGENT_TSHARK_PATH` environment variable. That's the only external dependency — everything else runs locally.

## Usage

```
python -m pcap_thread_agent.cli capture.pcapng -o report.md
```

## Tuning

Detector thresholds (port-scan fan-out count, beaconing regularity, exfil byte/ratio cutoffs, DNS query-length/entropy cutoffs, auth-failure count) are keyword arguments on the functions in `pcap_thread_agent/detectors.py` — adjust them there for your traffic baseline.

Narrative wording (summary templates, MITRE technique mapping, recommended next steps) lives in `pcap_thread_agent/narrative.py` — edit the per-type templates there if you want different phrasing.

## HTTP API (for a frontend, e.g. Lovable)

`pcap_thread_agent/api.py` wraps the same pipeline in a small FastAPI app so a web frontend can call it. The frontend never touches `tshark` directly — only this server does, and there's no other secret to manage.

Run locally:

```
uvicorn pcap_thread_agent.api:app --reload --port 8000
```

Or via Docker (bundles `tshark`, so this is the easiest way to host it):

```
docker build -t pcap-thread-agent .
docker run -p 8000:8000 pcap-thread-agent
```

### Endpoints

- `GET /health` — `{"status": "ok", "tshark": "<path>"}`, useful for confirming the deployment can find tshark.
- `POST /analyze` — multipart upload, field name `file`. Query params:
  - `format` (`json` default, or `markdown`).

  JSON response shape:
  ```json
  {
    "source_file": "capture.pcapng",
    "thread_count": 2,
    "threads": [
      {
        "id": "port_scan-10.0.0.50-...",
        "type": "port_scan",
        "severity": "high",
        "actor": "10.0.0.50",
        "targets": ["10.0.0.5"],
        "start_time": 1700000000.05,
        "end_time": 1700000000.89,
        "evidence": { "...": "..." },
        "narrative": "Summary: ...\nLikely technique: ...\nSeverity: ...\nRecommended next step: ..."
      }
    ]
  }
  ```

### Hosting it so Lovable can reach it

Lovable's generated frontend (and its Supabase edge functions, if you use them) can't run `tshark` or arbitrary subprocesses, so this API needs to live on infrastructure you control — a small VM, or a container host like Fly.io/Railway/Render using the included `Dockerfile`. Serverless/edge functions won't work here because they can't install native binaries.

Once it's deployed at a public HTTPS URL:

1. `API_ALLOWED_ORIGINS` defaults to `https://pcap-guardian.lovable.app`. Override it (comma-separated for multiple origins) if you add a custom domain or another frontend later.
2. In your Lovable project, call the API from the upload form:

   ```js
   const formData = new FormData();
   formData.append("file", file); // file: File from an <input type="file">

   const res = await fetch("https://your-api-host.example.com/analyze", {
     method: "POST",
     body: formData,
   });
   const data = await res.json();
   ```

3. Store the API's base URL as an environment variable in your Lovable project rather than hardcoding it, so you can point at a different deployment later without editing code.
