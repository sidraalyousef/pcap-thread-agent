FROM python:3.11-slim

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pcap_thread_agent ./pcap_thread_agent

ENV PCAP_AGENT_TSHARK_PATH=/usr/bin/tshark
EXPOSE 8000
CMD ["uvicorn", "pcap_thread_agent.api:app", "--host", "0.0.0.0", "--port", "8000"]
