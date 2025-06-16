#!/usr/bin/env python3

import nmap
import socket
import logging
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
import requests
import json
from pathlib import Path
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('port_scan.log'),
        logging.StreamHandler()
    ]
)

class PortScanner:
    def __init__(self, telegram_token=None, telegram_chat_id=None):
        self.nm = nmap.PortScanner()
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.dangerous_ports = {23, 3389}  # Telnet and RDP ports

    def resolve_host(self, target):
        """Resolve domain to IP if necessary."""
        try:
            if not self._is_ip(target):
                ip = socket.gethostbyname(target)
                logging.info(f"Resolved {target} to {ip}")
                return ip
            return target
        except socket.gaierror as e:
            logging.error(f"Failed to resolve hostname: {str(e)}")
            raise

    def _is_ip(self, address):
        """Check if the address is an IP."""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    def nmap_scan(self, target, ports="20-1024"):
        """Perform TCP SYN scan using Nmap."""
        try:
            logging.info(f"Starting Nmap scan on {target} for ports {ports}")
            self.nm.scan(target, ports, arguments='-sS -T4')
            return self.nm.get_nmap_last_output()
        except Exception as e:
            logging.error(f"Nmap scan failed: {str(e)}")
            raise

    def socket_scan(self, target, ports):
        """Validate open ports using socket connection."""
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception as e:
                logging.error(f"Socket scan failed for port {port}: {str(e)}")
        return open_ports

    def parse_nmap_xml(self, xml_output):
        """Parse Nmap XML output."""
        try:
            root = ET.fromstring(xml_output)
            open_ports = []
            
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    if port.find('state').get('state') == 'open':
                        port_id = int(port.get('portid'))
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        open_ports.append({
                            'port': port_id,
                            'service': service_name
                        })
            
            return open_ports
        except Exception as e:
            logging.error(f"Failed to parse Nmap XML: {str(e)}")
            raise

    def send_telegram_alert(self, message):
        """Send alert via Telegram."""
        if not self.telegram_token or not self.telegram_chat_id:
            return

        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": self.telegram_chat_id,
                "text": message,
                "parse_mode": "HTML"
            }
            response = requests.post(url, data=data)
            response.raise_for_status()
            logging.info("Telegram alert sent successfully")
        except Exception as e:
            logging.error(f"Failed to send Telegram alert: {str(e)}")

    def scan(self, target):
        """Perform complete scan of target."""
        try:
            # Resolve hostname if necessary
            ip = self.resolve_host(target)
            
            # Perform Nmap scan
            nmap_output = self.nmap_scan(ip)
            nmap_ports = self.parse_nmap_xml(nmap_output)
            
            # Get list of ports to validate
            ports_to_validate = [p['port'] for p in nmap_ports]
            
            # Perform socket scan validation
            socket_ports = self.socket_scan(ip, ports_to_validate)
            
            # Prepare results
            results = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'ip': ip,
                'nmap_scan': nmap_ports,
                'socket_validation': socket_ports,
                'dangerous_ports_found': [p for p in socket_ports if p in self.dangerous_ports]
            }
            
            # Log results
            self._log_results(results)
            
            # Check for dangerous ports and send alert if configured
            dangerous_ports = [p for p in socket_ports if p in self.dangerous_ports]
            if dangerous_ports:
                message = f"⚠️ <b>Security Alert</b>\n\n"
                message += f"Target: {target}\n"
                message += f"IP: {ip}\n"
                message += f"Dangerous ports found: {', '.join(map(str, dangerous_ports))}\n"
                self.send_telegram_alert(message)
            
            return results
            
        except Exception as e:
            logging.error(f"Scan failed: {str(e)}")
            raise

    def _log_results(self, results):
        """Log scan results to file."""
        try:
            log_file = 'scan_results.json'
            existing_results = []
            
            # Load existing results if file exists
            if Path(log_file).exists():
                with open(log_file, 'r') as f:
                    existing_results = json.load(f)
            
            # Append new results
            existing_results.append(results)
            
            # Save updated results
            with open(log_file, 'w') as f:
                json.dump(existing_results, f, indent=4)
            
            logging.info(f"Results logged to {log_file}")
        except Exception as e:
            logging.error(f"Failed to log results: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Port Scanner with Nmap and Socket Validation')
    parser.add_argument('target', help='Target IP address or domain name')
    parser.add_argument('--telegram-token', help='Telegram Bot Token for alerts')
    parser.add_argument('--telegram-chat-id', help='Telegram Chat ID for alerts')
    
    args = parser.parse_args()
    
    try:
        scanner = PortScanner(
            telegram_token=args.telegram_token,
            telegram_chat_id=args.telegram_chat_id
        )
        results = scanner.scan(args.target)
        
        # Print summary
        print("\nScan Results Summary:")
        print(f"Target: {results['target']}")
        print(f"IP: {results['ip']}")
        print("\nOpen Ports (Nmap):")
        for port in results['nmap_scan']:
            print(f"  Port {port['port']} - {port['service']}")
        print("\nValidated by Socket Scan:")
        for port in results['socket_validation']:
            print(f"  Port {port}")
        if results['dangerous_ports_found']:
            print("\n⚠️ Dangerous Ports Found:")
            for port in results['dangerous_ports_found']:
                print(f"  Port {port}")
        
    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 

#python port_scanner.py example.com
#python port_scanner.py example.com --telegram-token YOUR_BOT_TOKEN --telegram-chat-id YOUR_CHAT_ID