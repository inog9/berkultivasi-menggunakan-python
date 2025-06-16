#!/usr/bin/env python3

import re
import json
import logging
import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import sys

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('analisis_keamanan.log'),
        logging.StreamHandler()
    ]
)

class AnalisisLogKeamanan:
    def __init__(self):
        # Pola regex untuk berbagai jenis log
        self.pola = {
            'auth_gagal': re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)'),
            'auth_berhasil': re.compile(r'Accepted password for (\S+) from (\S+)'),
            'web_admin': re.compile(r'(\S+) - - \[(.*?)\] "GET /admin'),
            'proses_mencurigakan': re.compile(r'(\S+) started process (\S+)')
        }
        
        # Struktur data untuk analisis
        self.events = []
        self.ip_ke_user = defaultdict(set)
        self.user_ke_ip = defaultdict(set)
        self.ip_ke_sumber = defaultdict(set)
        self.alert = []

    def baca_file_log(self, file_log, jenis_log):
        """Baca dan parse file log sesuai jenisnya."""
        try:
            with open(file_log, 'r') as f:
                for baris in f:
                    event = self.parse_baris_log(baris, jenis_log)
                    if event:
                        self.events.append(event)
                        # Update mapping
                        if 'ip' in event and 'user' in event:
                            self.ip_ke_user[event['ip']].add(event['user'])
                            self.user_ke_ip[event['user']].add(event['ip'])
                        if 'ip' in event:
                            self.ip_ke_sumber[event['ip']].add(jenis_log)
            
            logging.info(f"Berhasil membaca file log {jenis_log}: {file_log}")
        except Exception as e:
            logging.error(f"Error membaca file log {jenis_log}: {str(e)}")
            raise

    def parse_baris_log(self, baris, jenis_log):
        """Parse satu baris log sesuai jenisnya."""
        try:
            # Ekstrak timestamp
            timestamp_match = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', baris)
            timestamp = timestamp_match.group(1) if timestamp_match else None

            if jenis_log == 'auth':
                # Cek login gagal
                gagal_match = self.pola['auth_gagal'].search(baris)
                if gagal_match:
                    return {
                        'timestamp': timestamp,
                        'jenis': 'login_gagal',
                        'user': gagal_match.group(1),
                        'ip': gagal_match.group(2),
                        'sumber': 'auth'
                    }
                
                # Cek login berhasil
                berhasil_match = self.pola['auth_berhasil'].search(baris)
                if berhasil_match:
                    return {
                        'timestamp': timestamp,
                        'jenis': 'login_berhasil',
                        'user': berhasil_match.group(1),
                        'ip': berhasil_match.group(2),
                        'sumber': 'auth'
                    }

            elif jenis_log == 'web':
                # Cek akses admin
                admin_match = self.pola['web_admin'].search(baris)
                if admin_match:
                    return {
                        'timestamp': timestamp,
                        'jenis': 'akses_admin',
                        'ip': admin_match.group(1),
                        'sumber': 'web'
                    }

            elif jenis_log == 'proses':
                # Cek proses mencurigakan
                proses_match = self.pola['proses_mencurigakan'].search(baris)
                if proses_match:
                    return {
                        'timestamp': timestamp,
                        'jenis': 'proses_mencurigakan',
                        'user': proses_match.group(1),
                        'proses': proses_match.group(2),
                        'sumber': 'proses'
                    }

            return None

        except Exception as e:
            logging.error(f"Error parsing baris log: {str(e)}")
            return None

    def analisis_korelasi(self):
        """Analisis korelasi antar event untuk deteksi insiden."""
        # 1. Deteksi login gagal diikuti akses admin
        for i, event in enumerate(self.events):
            if event['jenis'] == 'login_gagal':
                ip = event['ip']
                # Cek 10 event berikutnya untuk akses admin dari IP yang sama
                for next_event in self.events[i+1:i+11]:
                    if (next_event['jenis'] == 'akses_admin' and 
                        next_event['ip'] == ip):
                        self.alert.append({
                            'tipe': 'login_gagal_akses_admin',
                            'severity': 'tinggi',
                            'detail': {
                                'ip': ip,
                                'user': event['user'],
                                'timestamp_login': event['timestamp'],
                                'timestamp_admin': next_event['timestamp']
                            }
                        })

        # 2. Deteksi IP muncul di multiple sumber
        for ip, sumber in self.ip_ke_sumber.items():
            if len(sumber) > 1:
                self.alert.append({
                    'tipe': 'ip_multiple_sumber',
                    'severity': 'sedang',
                    'detail': {
                        'ip': ip,
                        'sumber': list(sumber)
                    }
                })

        # 3. Deteksi user dari multiple IP
        for user, ip_list in self.user_ke_ip.items():
            if len(ip_list) > 2:
                self.alert.append({
                    'tipe': 'user_multiple_ip',
                    'severity': 'sedang',
                    'detail': {
                        'user': user,
                        'ip_list': list(ip_list)
                    }
                })

    def ekspor_hasil(self, file_output):
        """Ekspor hasil analisis ke file JSON."""
        try:
            hasil = {
                'timestamp_analisis': datetime.now().isoformat(),
                'ringkasan': {
                    'total_event': len(self.events),
                    'total_alert': len(self.alert),
                    'ip_unik': len(self.ip_ke_user),
                    'user_unik': len(self.user_ke_ip)
                },
                'alert': self.alert,
                'statistik_ip': {
                    ip: {
                        'jumlah_user': len(users),
                        'sumber': list(self.ip_ke_sumber[ip])
                    }
                    for ip, users in self.ip_ke_user.items()
                }
            }
            
            with open(file_output, 'w') as f:
                json.dump(hasil, f, indent=4)
            logging.info(f"Hasil diekspor ke {file_output}")
        except Exception as e:
            logging.error(f"Error mengekspor hasil: {str(e)}")
            raise

    def tampilkan_ringkasan(self):
        """Tampilkan ringkasan hasil analisis."""
        print("\nRingkasan Analisis Log Keamanan:")
        print("=" * 50)
        print(f"Total Event: {len(self.events)}")
        print(f"Total Alert: {len(self.alert)}")
        print(f"IP Unik: {len(self.ip_ke_user)}")
        print(f"User Unik: {len(self.user_ke_ip)}")
        
        print("\nAlert Keamanan:")
        print("-" * 50)
        for alert in self.alert:
            print(f"\nTipe: {alert['tipe']}")
            print(f"Severity: {alert['severity']}")
            print("Detail:")
            for key, value in alert['detail'].items():
                print(f"  {key}: {value}")
            print("-" * 30)

def main():
    parser = argparse.ArgumentParser(description='Analisis Log Keamanan')
    parser.add_argument('--auth-log', help='Path ke file log auth')
    parser.add_argument('--web-log', help='Path ke file log web')
    parser.add_argument('--proses-log', help='Path ke file log proses')
    parser.add_argument('--output', default='hasil_analisis.json',
                      help='File output JSON (default: hasil_analisis.json)')
    
    args = parser.parse_args()
    
    try:
        analyzer = AnalisisLogKeamanan()
        
        if args.auth_log:
            analyzer.baca_file_log(args.auth_log, 'auth')
        if args.web_log:
            analyzer.baca_file_log(args.web_log, 'web')
        if args.proses_log:
            analyzer.baca_file_log(args.proses_log, 'proses')
            
        analyzer.analisis_korelasi()
        analyzer.ekspor_hasil(args.output)
        analyzer.tampilkan_ringkasan()
        
    except Exception as e:
        logging.error(f"Analisis gagal: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 

#python analisis_log_keamanan.py \
 #   --auth-log /var/log/auth.log \
#    --web-log /var/log/nginx/access.log \
  #  --proses-log /var/log/audit/audit.log \
  #  --output hasil_analisis.json