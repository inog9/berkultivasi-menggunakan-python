#pip install splunk-sdk requests

import yaml
import requests
import splunklib.client as client
import splunklib.results as results
from datetime import datetime

# 1. Load configuration
with open("config.yaml") as f:
    config = yaml.safe_load(f)

splunk_cfg = config["splunk"]
hunt_cfg   = config["hunt"]
noti_cfg   = config["notification"]

# 2. Authenticate to Splunk
service = client.Service(
    host=splunk_cfg["host"],
    port=splunk_cfg["port"],
    username=splunk_cfg["username"],
    password=splunk_cfg["password"]
)
if not service.is_authenticated():
    raise RuntimeError("Unable to authenticate to Splunk")

# 3. Fetch IOCs (if needed for enrichment)
def fetch_iocs(url):
    """
    Retrieve IOCs from external feed (e.g., JSON list of malicious IPs).
    """
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()  # assume JSON array of strings

iocs = fetch_iocs(hunt_cfg["ioc_feed_url"])

# 4. Execute a hunt (search) and retrieve results
def run_hunt(name, query, earliest="-24h", latest="now"):
    """
    Submit a blocking Splunk search job and return list of result dicts.
    """
    # Prep a time-bounded search
    search_str = f"search {query} earliest_time={earliest} latest_time={latest}"
    job = service.jobs.create(search_str, exec_mode="blocking")
    reader = results.JSONResultsReader(job.results())
    records = [dict(item) for item in reader if isinstance(item, dict)]
    return records

# 5. Enrich and evaluate hunt results
def enrich_and_alert(hunt_name, records):
    """
    Enrich results (e.g., tag IOC hits) and send notification if above threshold.
    """
    count = len(records)
    if count <= hunt_cfg["alert_threshold"]:
        return  # nothing to alert

    # Optional enrichment: tag any IOC matches in fields
    for rec in records:
        for field, val in rec.items():
            if val in iocs:
                rec.setdefault("ioc_matched", []).append(val)

    # Build notification payload
    message = {
        "text": f"*Hunt:* {hunt_name}\n*Time:* {datetime.utcnow().isoformat()}Z\n*Results:* {count} records"
    }
    # Include first few records in message
    message["attachments"] = [{
        "title": "Sample records",
        "fields": [
            {"title": k, "value": str(v), "short": True}
            for k, v in list(records[0].items())[:5]
        ]
    }]

    # Send to Slack
    resp = requests.post(noti_cfg["slack_webhook"], json=message, timeout=5)
    resp.raise_for_status()

# 6. Orchestrator: iterate all hunts
def main():
    for hunt in hunt_cfg["searches"]:
        name  = hunt["name"]
        query = hunt["query"]
        print(f"Running hunt: {name}")
        results = run_hunt(name, query)
        print(f"  Found {len(results)} records")
        enrich_and_alert(name, results)

if __name__ == "__main__":
    main()
