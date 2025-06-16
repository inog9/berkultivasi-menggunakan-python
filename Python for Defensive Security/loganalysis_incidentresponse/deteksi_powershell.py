#!/usr/bin/env python3

import os
import sys
import json
import yara
import logging
import argparse
from datetime import datetime
from pathlib import Path
#pip install yara-python

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('deteksi_powershell.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# YARA rule untuk mendeteksi PowerShell yang di-encode base64
POWERSHELL_RULE = """
rule Base64EncodedPowerShell {
    meta:
        description = "Deteksi PowerShell yang di-encode base64"
        author = "Security Analyst"
        date = "2024-03-14"
        severity = "High"
    
    strings:
        // Pattern untuk PowerShell yang di-encode base64
        $base64_powershell = /[A-Za-z0-9+/]{20,}={0,2}/
        $powershell_indicators = /powershell|iex|invoke-expression|executionpolicy|bypass/i
        
    condition:
        // Cek apakah ada string base64 yang cukup panjang
        // dan mengandung indikator PowerShell
        any of ($base64_powershell) and
        any of ($powershell_indicators)
}
"""

class PowerShellDetector:
    def __init__(self, rules):
        self.rules = yara.compile(source=rules)
        self.matches = []

    def scan_file(self, file_path):
        """Scan file dengan YARA rules"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            matches = self.rules.match(data=content)
            
            if matches:
                # Ekstrak konteks untuk setiap match
                match_details = []
                for match in matches:
                    for string in match.strings:
                        # Ambil konteks sekitar string yang match
                        start = max(0, string[0] - 50)
                        end = min(len(content), string[0] + 50)
                        context = content[start:end]
                        
                        match_details.append({
                            'rule': match.rule,
                            'string': string[2].decode('utf-8', errors='ignore'),
                            'offset': string[0],
                            'context': context
                        })
                
                return {
                    'file': str(file_path),
                    'matches': match_details,
                    'timestamp': datetime.now().isoformat()
                }
            
            return None

        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {str(e)}")
            return None

    def scan_directory(self, directory):
        """Scan semua file .ps1 dalam direktori"""
        directory = Path(directory)
        
        if not directory.exists():
            logging.error(f"Directory not found: {directory}")
            return
        
        for file_path in directory.rglob('*.ps1'):
            logging.info(f"Scanning: {file_path}")
            result = self.scan_file(file_path)
            
            if result:
                self.matches.append(result)
                logging.warning(f"Match found in: {file_path}")

    def save_results(self, output_file):
        """Simpan hasil ke file JSON"""
        try:
            with open(output_file, 'w') as f:
                json.dump({
                    'scan_time': datetime.now().isoformat(),
                    'total_matches': len(self.matches),
                    'matches': self.matches
                }, f, indent=2)
            
            logging.info(f"Results saved to: {output_file}")
            
        except Exception as e:
            logging.error(f"Error saving results: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Deteksi PowerShell yang di-encode base64')
    parser.add_argument('directory', help='Direktori yang akan di-scan')
    parser.add_argument('-o', '--output', help='File output JSON', default='base64_powershell_alerts.json')
    
    args = parser.parse_args()

    try:
        # Inisialisasi detector
        detector = PowerShellDetector(POWERSHELL_RULE)
        
        # Scan direktori
        detector.scan_directory(args.directory)
        
        # Simpan hasil
        detector.save_results(args.output)
        
        # Tampilkan ringkasan
        if detector.matches:
            logging.warning(f"Found {len(detector.matches)} files with potential base64-encoded PowerShell")
        else:
            logging.info("No matches found")

    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 

#python deteksi_powershell.py /path/to/scripts -o base64_powershell_alerts.json