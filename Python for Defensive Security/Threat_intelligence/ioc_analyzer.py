#!/usr/bin/env python3

import json
import time
import logging
import argparse
import requests
from datetime import datetime, timedelta
from pathlib import Path
import redis
from functools import lru_cache
import hashlib
import sys

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ioc_analysis.log'),
        logging.StreamHandler()
    ]
)

class IOCAnalyzer:
    def __init__(self, redis_host='localhost', redis_port=6379):
        # Konfigurasi API
        self.api_config = {
            'virustotal': {
                'base_url': 'https://www.virustotal.com/vtapi/v2',
                'rate_limit': 4,  # requests per minute
                'last_request': 0
            },
            'abuseipdb': {
                'base_url': 'https://api.abuseipdb.com/api/v2',
                'rate_limit': 2,  # requests per minute
                'last_request': 0
            }
        }
        
        # Inisialisasi Redis untuk caching
        try:
            self.redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                decode_responses=True
            )
            logging.info("Berhasil terhubung ke Redis")
        except Exception as e:
            logging.error(f"Error koneksi Redis: {str(e)}")
            self.redis_client = None

    def _generate_cache_key(self, ioc, source):
        """Generate cache key untuk IOC."""
        return f"ioc:{source}:{hashlib.md5(ioc.encode()).hexdigest()}"

    def _check_cache(self, ioc, source):
        """Cek hasil di cache."""
        if not self.redis_client:
            return None
        
        cache_key = self._generate_cache_key(ioc, source)
        cached_data = self.redis_client.get(cache_key)
        
        if cached_data:
            data = json.loads(cached_data)
            # Cek apakah cache masih valid (24 jam)
            if datetime.fromisoformat(data['timestamp']) > datetime.now() - timedelta(hours=24):
                logging.info(f"Cache hit untuk {ioc} dari {source}")
                return data['result']
        return None

    def _update_cache(self, ioc, source, result):
        """Update cache dengan hasil baru."""
        if not self.redis_client:
            return
        
        cache_key = self._generate_cache_key(ioc, source)
        cache_data = {
            'timestamp': datetime.now().isoformat(),
            'result': result
        }
        self.redis_client.setex(
            cache_key,
            timedelta(hours=24),
            json.dumps(cache_data)
        )

    def _respect_rate_limit(self, source):
        """Implementasi rate limiting."""
        config = self.api_config[source]
        current_time = time.time()
        time_since_last = current_time - config['last_request']
        
        if time_since_last < (60 / config['rate_limit']):
            sleep_time = (60 / config['rate_limit']) - time_since_last
            logging.info(f"Rate limit untuk {source}, menunggu {sleep_time:.2f} detik")
            time.sleep(sleep_time)
        
        config['last_request'] = time.time()

    def _retry_with_backoff(self, func, max_retries=3):
        """Implementasi retry dengan exponential backoff."""
        for attempt in range(max_retries):
            try:
                return func()
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    raise
                wait_time = (2 ** attempt) * 1  # 1, 2, 4 detik
                logging.warning(f"Request gagal, mencoba lagi dalam {wait_time} detik: {str(e)}")
                time.sleep(wait_time)

    def query_virustotal(self, ioc):
        """Query VirusTotal API dengan rate limiting dan caching."""
        # Cek cache dulu
        cached_result = self._check_cache(ioc, 'virustotal')
        if cached_result:
            return cached_result

        self._respect_rate_limit('virustotal')
        
        def make_request():
            response = requests.get(
                f"{self.api_config['virustotal']['base_url']}/ip-address/report",
                params={'apikey': 'YOUR_VT_API_KEY', 'ip': ioc}
            )
            response.raise_for_status()
            return response.json()

        result = self._retry_with_backoff(make_request)
        self._update_cache(ioc, 'virustotal', result)
        return result

    def query_abuseipdb(self, ioc):
        """Query AbuseIPDB API dengan rate limiting dan caching."""
        cached_result = self._check_cache(ioc, 'abuseipdb')
        if cached_result:
            return cached_result

        self._respect_rate_limit('abuseipdb')
        
        def make_request():
            response = requests.get(
                f"{self.api_config['abuseipdb']['base_url']}/check",
                params={'ipAddress': ioc},
                headers={'Key': 'YOUR_ABUSEIPDB_API_KEY'}
            )
            response.raise_for_status()
            return response.json()

        result = self._retry_with_backoff(make_request)
        self._update_cache(ioc, 'abuseipdb', result)
        return result

    def analyze_ioc(self, ioc, min_confidence=70, days_threshold=30):
        """Analisis IOC dari multiple sumber."""
        results = {
            'ioc': ioc,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'aggregated_score': 0,
            'tags': set()
        }

        # Query semua sumber
        try:
            vt_result = self.query_virustotal(ioc)
            results['sources']['virustotal'] = {
                'score': vt_result.get('positives', 0) / vt_result.get('total', 1) * 100,
                'last_seen': vt_result.get('last_seen'),
                'detections': vt_result.get('detections', [])
            }
            results['tags'].update(vt_result.get('tags', []))

            abuse_result = self.query_abuseipdb(ioc)
            results['sources']['abuseipdb'] = {
                'score': abuse_result.get('data', {}).get('abuseConfidenceScore', 0),
                'last_seen': abuse_result.get('data', {}).get('lastSeenAt'),
                'reports': abuse_result.get('data', {}).get('totalReports', 0)
            }
            if abuse_result.get('data', {}).get('abuseConfidenceScore', 0) > 50:
                results['tags'].add('high_abuse_score')

        except Exception as e:
            logging.error(f"Error querying sources untuk {ioc}: {str(e)}")
            return None

        # Hitung aggregated score
        scores = [
            results['sources']['virustotal']['score'],
            results['sources']['abuseipdb']['score']
        ]
        results['aggregated_score'] = sum(scores) / len(scores)

        # Filter berdasarkan confidence dan last seen
        if results['aggregated_score'] < min_confidence:
            logging.info(f"IOC {ioc} diabaikan karena score rendah: {results['aggregated_score']}")
            return None

        # Normalisasi untuk SIEM
        results['siem_data'] = {
            'event_type': 'ioc_analysis',
            'severity': 'high' if results['aggregated_score'] > 80 else 'medium',
            'confidence': results['aggregated_score'],
            'tags': list(results['tags']),
            'sources': list(results['sources'].keys()),
            'timestamp': results['timestamp']
        }

        return results

    def export_results(self, results, output_file):
        """Ekspor hasil analisis ke file JSON."""
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            logging.info(f"Hasil diekspor ke {output_file}")
        except Exception as e:
            logging.error(f"Error mengekspor hasil: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description='IOC Analyzer dengan Rate Limiting dan Caching')
    parser.add_argument('ioc_file', help='File berisi daftar IOC (satu per baris)')
    parser.add_argument('--output', default='hasil_ioc.json',
                      help='File output JSON (default: hasil_ioc.json)')
    parser.add_argument('--min-confidence', type=int, default=70,
                      help='Minimum confidence score (default: 70)')
    parser.add_argument('--days-threshold', type=int, default=30,
                      help='Threshold hari untuk last seen (default: 30)')
    
    args = parser.parse_args()
    
    if not Path(args.ioc_file).exists():
        logging.error(f"File IOC tidak ditemukan: {args.ioc_file}")
        sys.exit(1)
    
    try:
        analyzer = IOCAnalyzer()
        results = []
        
        with open(args.ioc_file, 'r') as f:
            for line in f:
                ioc = line.strip()
                if ioc:
                    result = analyzer.analyze_ioc(
                        ioc,
                        min_confidence=args.min_confidence,
                        days_threshold=args.days_threshold
                    )
                    if result:
                        results.append(result)
        
        analyzer.export_results(results, args.output)
        
    except Exception as e:
        logging.error(f"Analisis gagal: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 