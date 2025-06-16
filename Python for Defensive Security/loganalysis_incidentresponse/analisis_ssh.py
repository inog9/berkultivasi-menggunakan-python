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
        logging.FileHandler('analisis_ssh.log'),
        logging.StreamHandler()
    ]
)

class AnalisisSSH:
    def __init__(self):
        # Pola regex untuk parsing log SSH
        self.pola = {
            'gagal_password': re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)'),
            'user_tidak_valid': re.compile(r'Invalid user (\S+) from (\S+)'),
            'koneksi_tertutup': re.compile(r'Connection closed by (\S+) port (\d+)'),
            'login_berhasil': re.compile(r'Accepted password for (\S+) from (\S+) port (\d+)')
        }
        
        # Inisialisasi penghitung
        self.attempt_gagal = defaultdict(list)
        self.user_tidak_valid = defaultdict(list)
        self.login_berhasil = defaultdict(list)

    def parse_baris_log(self, baris):
        """Parse satu baris log dan ekstrak informasi yang relevan."""
        try:
            # Ekstrak timestamp jika ada
            timestamp_match = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', baris)
            timestamp = timestamp_match.group(1) if timestamp_match else None

            # Cek percobaan password gagal
            gagal_match = self.pola['gagal_password'].search(baris)
            if gagal_match:
                return {
                    'timestamp': timestamp,
                    'tipe': 'gagal_password',
                    'username': gagal_match.group(1),
                    'ip': gagal_match.group(2),
                    'port': gagal_match.group(3)
                }

            # Cek percobaan user tidak valid
            invalid_match = self.pola['user_tidak_valid'].search(baris)
            if invalid_match:
                return {
                    'timestamp': timestamp,
                    'tipe': 'user_tidak_valid',
                    'username': invalid_match.group(1),
                    'ip': invalid_match.group(2)
                }

            # Cek login berhasil
            berhasil_match = self.pola['login_berhasil'].search(baris)
            if berhasil_match:
                return {
                    'timestamp': timestamp,
                    'tipe': 'login_berhasil',
                    'username': berhasil_match.group(1),
                    'ip': berhasil_match.group(2),
                    'port': berhasil_match.group(3)
                }

            return None

        except Exception as e:
            logging.error(f"Error saat parsing baris: {str(e)}")
            return None

    def analisis_file_log(self, file_log):
        """Analisis file syslog dan hitung percobaan gagal."""
        try:
            with open(file_log, 'r') as f:
                for baris in f:
                    hasil = self.parse_baris_log(baris)
                    if hasil:
                        if hasil['tipe'] == 'gagal_password':
                            self.attempt_gagal[hasil['ip']].append(hasil)
                        elif hasil['tipe'] == 'user_tidak_valid':
                            self.user_tidak_valid[hasil['ip']].append(hasil)
                        elif hasil['tipe'] == 'login_berhasil':
                            self.login_berhasil[hasil['ip']].append(hasil)

            logging.info(f"Berhasil menganalisis file log: {file_log}")
        except Exception as e:
            logging.error(f"Error saat menganalisis file log: {str(e)}")
            raise

    def buat_laporan(self):
        """Buat laporan komprehensif dari analisis."""
        laporan = {
            'timestamp': datetime.now().isoformat(),
            'ringkasan': {
                'total_attempt_gagal': sum(len(attempts) for attempts in self.attempt_gagal.values()),
                'total_user_tidak_valid': sum(len(attempts) for attempts in self.user_tidak_valid.values()),
                'total_login_berhasil': sum(len(attempts) for attempts in self.login_berhasil.values()),
                'jumlah_penyerang_unik': len(self.attempt_gagal)
            },
            'attempt_gagal_per_ip': {
                ip: {
                    'jumlah': len(attempts),
                    'attempts': attempts
                }
                for ip, attempts in self.attempt_gagal.items()
            },
            'user_tidak_valid_per_ip': {
                ip: {
                    'jumlah': len(attempts),
                    'attempts': attempts
                }
                for ip, attempts in self.user_tidak_valid.items()
            },
            'login_berhasil_per_ip': {
                ip: {
                    'jumlah': len(attempts),
                    'attempts': attempts
                }
                for ip, attempts in self.login_berhasil.items()
            }
        }
        return laporan

    def ekspor_hasil(self, file_output):
        """Ekspor hasil analisis ke file JSON."""
        try:
            laporan = self.buat_laporan()
            with open(file_output, 'w') as f:
                json.dump(laporan, f, indent=4)
            logging.info(f"Hasil diekspor ke {file_output}")
        except Exception as e:
            logging.error(f"Error saat mengekspor hasil: {str(e)}")
            raise

    def tampilkan_ringkasan(self):
        """Tampilkan ringkasan hasil analisis."""
        laporan = self.buat_laporan()
        ringkasan = laporan['ringkasan']
        
        print("\nRingkasan Analisis Login SSH:")
        print("=" * 50)
        print(f"Total Percobaan Gagal: {ringkasan['total_attempt_gagal']}")
        print(f"Total User Tidak Valid: {ringkasan['total_user_tidak_valid']}")
        print(f"Total Login Berhasil: {ringkasan['total_login_berhasil']}")
        print(f"Jumlah Penyerang Unik: {ringkasan['jumlah_penyerang_unik']}")
        
        print("\n5 IP Teratas dengan Percobaan Gagal:")
        print("-" * 50)
        ip_terurut = sorted(
            self.attempt_gagal.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:5]
        
        for ip, attempts in ip_terurut:
            print(f"IP: {ip}")
            print(f"Jumlah Percobaan Gagal: {len(attempts)}")
            print(f"Jumlah Username Dicoba: {len(set(a['username'] for a in attempts))}")
            print("-" * 30)

def main():
    parser = argparse.ArgumentParser(description='Analisis Percobaan Login SSH')
    parser.add_argument('file_log', help='Path ke file syslog')
    parser.add_argument('--output', default='analisis_ssh.json',
                      help='File output JSON (default: analisis_ssh.json)')
    
    args = parser.parse_args()
    
    if not Path(args.file_log).exists():
        logging.error(f"File log tidak ditemukan: {args.file_log}")
        sys.exit(1)
    
    try:
        analyzer = AnalisisSSH()
        analyzer.analisis_file_log(args.file_log)
        analyzer.ekspor_hasil(args.output)
        analyzer.tampilkan_ringkasan()
    except Exception as e:
        logging.error(f"Analisis gagal: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 