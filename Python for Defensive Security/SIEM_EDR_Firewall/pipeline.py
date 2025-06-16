import json
import yaml
import requests
from datetime import datetime

# 3.1 Load configuration (rules, thresholds, API keys)
with open("pipeline_config.yaml") as cfg:
    config = yaml.safe_load(cfg)

TI_API_KEY = config["threat_intel"]["api_key"]
SIEM_HEC = config["siem"]["hec_url"]
SIEM_TOKEN = config["siem"]["hec_token"]

# 3.2 Ingestion: read from a log file (could be Kafka, HTTP, etc.)
def ingest_logs(filepath):
    """
    Yield one log record (JSON) per line.
    """
    with open(filepath) as f:
        for line in f:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue  # skip malformed

# 3.3 Normalization: map vendor fields to common schema
def normalize(record):
    """
    Convert raw record into standardized dict.
    Expected raw fields: timestamp, src_ip, dst_ip, event_type
    """
    return {
        "timestamp": datetime.fromisoformat(record["timestamp"]),
        "src_ip": record.get("src_ip"),
        "dst_ip": record.get("dst_ip"),
        "user": record.get("user", "").lower(),
        "event": record.get("event_type")
    }

# 3.4 Enrichment: add IP reputation
def enrich_ip(ip):
    """
    Query an external Threat Intel API for reputation score.
    """
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": TI_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 30}
    resp = requests.get(url, headers=headers, params=params, timeout=5)
    if resp.status_code == 200:
        data = resp.json().get("data", {})
        return data.get("abuseConfidenceScore", 0)
    return 0

# 3.5 Detection: simple threshold-based rule
def detect(record):
    """
    Return True if event should trigger alert.
    E.g., if IP abuse score exceeds threshold or repeated failures.
    """
    alerts = []
    score = enrich_ip(record["src_ip"])
    if score >= config["detection"]["ip_reputation_threshold"]:
        alerts.append(f"High abuse score: {record['src_ip']} = {score}")
    # Example: brute-force detection
    if record["event"] == "failed_login":
        # In real code, track counts per IP (e.g., in Redis)
        # Here we simulate with a single-event rule:
        alerts.append(f"Failed login: {record['src_ip']}")
    return alerts

# 3.6 Output: send alerts to SIEM via HEC
def send_to_siem(alerts, record):
    """
    Send a list of alert messages to SIEM HEC.
    """
    for msg in alerts:
        payload = {
            "time": record["timestamp"].timestamp(),
            "host": "pipeline_host",
            "sourcetype": "custom:alerts",
            "event": {
                "message": msg,
                "src_ip": record["src_ip"],
                "event": record["event"]
            }
        }
        headers = {"Authorization": f"Splunk {SIEM_TOKEN}"}
        resp = requests.post(SIEM_HEC, json=payload, headers=headers, timeout=3)
        if resp.status_code not in (200, 201, 202):
            # handle failure (log, retry, dead-letter)
            print(f"HEC error: {resp.status_code} {resp.text}")

# 3.7 Orchestrator: tie stages together
def run_pipeline(logfile):
    """
    Main function to run the detection pipeline.
    """
    for raw in ingest_logs(logfile):
        norm = normalize(raw)
        alerts = detect(norm)
        if alerts:
            send_to_siem(alerts, norm)

if __name__ == "__main__":
    run_pipeline("raw_events.jsonl")
