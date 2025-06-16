#!/usr/bin/env python3

import csv
import json
import logging
import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path
import pandas as pd
from jinja2 import Template

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_analysis.log'),
        logging.StreamHandler()
    ]
)

class FirewallAnalyzer:
    def __init__(self, threshold=50):
        self.threshold = threshold
        self.failed_attempts = Counter()
        self.template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Firewall Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .warning { color: red; }
            </style>
        </head>
        <body>
            <h1>Firewall Analysis Report</h1>
            <p>Generated on: {{ timestamp }}</p>
            <h2>Top 5 Offending IPs</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Failed Attempts</th>
                    <th>Status</th>
                </tr>
                {% for ip, count in top_offenders %}
                <tr>
                    <td>{{ ip }}</td>
                    <td>{{ count }}</td>
                    <td class="{% if count > threshold %}warning{% endif %}">
                        {% if count > threshold %}WARNING{% else %}Normal{% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """

    def read_logs(self, log_file):
        """Read firewall logs from CSV file."""
        try:
            with open(log_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('status', '').lower() in ['failed', 'denied', 'blocked']:
                        ip = row.get('source_ip', '')
                        if ip:
                            self.failed_attempts[ip] += 1
            logging.info(f"Successfully processed log file: {log_file}")
        except Exception as e:
            logging.error(f"Error reading log file: {str(e)}")
            raise

    def analyze(self):
        """Analyze the logs and generate reports."""
        # Get top 5 offenders
        top_offenders = self.failed_attempts.most_common(5)
        
        # Log warnings for IPs exceeding threshold
        for ip, count in self.failed_attempts.items():
            if count > self.threshold:
                logging.warning(f"IP {ip} exceeded threshold with {count} failed attempts")

        # Prepare data for reports
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_data = {
            'timestamp': timestamp,
            'top_offenders': top_offenders,
            'threshold': self.threshold
        }

        # Generate reports
        self._generate_json_report(report_data)
        self._generate_csv_report(top_offenders)
        self._generate_html_report(report_data)

    def _generate_json_report(self, data):
        """Generate JSON report."""
        try:
            with open('firewall_report.json', 'w') as f:
                json.dump(data, f, indent=4)
            logging.info("JSON report generated successfully")
        except Exception as e:
            logging.error(f"Error generating JSON report: {str(e)}")

    def _generate_csv_report(self, top_offenders):
        """Generate CSV report."""
        try:
            with open('firewall_report.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address', 'Failed Attempts', 'Status'])
                for ip, count in top_offenders:
                    status = 'WARNING' if count > self.threshold else 'Normal'
                    writer.writerow([ip, count, status])
            logging.info("CSV report generated successfully")
        except Exception as e:
            logging.error(f"Error generating CSV report: {str(e)}")

    def _generate_html_report(self, data):
        """Generate HTML report."""
        try:
            template = Template(self.template)
            html_content = template.render(**data)
            with open('firewall_report.html', 'w') as f:
                f.write(html_content)
            logging.info("HTML report generated successfully")
        except Exception as e:
            logging.error(f"Error generating HTML report: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Firewall Log Analyzer')
    parser.add_argument('log_file', help='Path to the firewall log CSV file')
    parser.add_argument('--threshold', type=int, default=50,
                      help='Threshold for failed attempts (default: 50)')
    
    args = parser.parse_args()
    
    if not Path(args.log_file).exists():
        logging.error(f"Log file not found: {args.log_file}")
        return
    
    try:
        analyzer = FirewallAnalyzer(threshold=args.threshold)
        analyzer.read_logs(args.log_file)
        analyzer.analyze()
        logging.info("Analysis completed successfully")
    except Exception as e:
        logging.error(f"Analysis failed: {str(e)}")

if __name__ == "__main__":
    main() 


#pip install pandas jinja2
#python firewall_analyzer.py path/to/firewall_logs.csv --threshold 50