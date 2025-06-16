import re
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
LOG_PATH       = "/var/log/auth.log"
PATTERN        = re.compile(r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)")
ALERT_WINDOW   = timedelta(minutes=5)  # suppress duplicate alerts per IP
SLACK_WEBHOOK  = "https://hooks.slack.com/services/XXXXX/XXXXX/XXXXX"

# In-memory store of last alert times per IP
last_alert_time = defaultdict(lambda: datetime.min)

def send_slack_notification(ip, count):
    """
    Send an alert to Slack via Incoming Webhook.
    """
    payload = {
        "text": f"Security Alert: {count} failed logins detected from {ip}"
    }
    resp = requests.post(SLACK_WEBHOOK, json=payload, timeout=3)
    resp.raise_for_status()

def respond_to_incident(ip):
    """
    Placeholder for automated response logic, e.g., adding firewall rule.
    """
    # Example: call firewall API to block IP
    # block_ip_on_firewall(ip)
    print(f"[{datetime.now()}] Responding by blocking IP {ip}")

class LogHandler(FileSystemEventHandler):
    """
    Watches for file modifications and processes new lines.
    """
    def __init__(self, path):
        super().__init__()
        self.path   = path
        self._inode = None
        self._file  = None
        self._seek_to_end()

    def _seek_to_end(self):
        """
        Open file, remember inode, and seek to end so we read only new lines.
        """
        self._file = open(self.path, "r")
        self._inode = self._file.fileno()
        self._file.seek(0, 2)

    def on_modified(self, event):
        """
        Called whenever the watched file is written to.
        """
        if event.src_path != self.path:
            return
        # Read all new lines
        for line in self._file:
            self.process_line(line.strip())

    def process_line(self, line):
        """
        Apply detection logic to each line.
        """
        match = PATTERN.search(line)
        if not match:
            return
        ip = match.group("ip")
        now = datetime.now()

        # Suppress duplicate alerts within ALERT_WINDOW
        if now - last_alert_time[ip] < ALERT_WINDOW:
            return

        # Count occurrences in the window (could be replaced with more complex state)
        last_alert_time[ip] = now
        # In real code, you might track counts in a deque for sliding-window logic

        # Trigger alert and response in separate threads to avoid blocking
        threading.Thread(target=send_slack_notification, args=(ip, 1), daemon=True).start()
        threading.Thread(target=respond_to_incident, args=(ip,), daemon=True).start()

def start_monitoring():
    """
    Initialize watchdog observer to monitor the log file.
    """
    event_handler = LogHandler(LOG_PATH)
    observer = Observer()
    observer.schedule(event_handler, path=LOG_PATH, recursive=False)
    observer.start()
    print(f"Started monitoring {LOG_PATH} for failed login patterns.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_monitoring()
