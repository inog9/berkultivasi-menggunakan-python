#!/usr/bin/env python3

import os
import json
import hashlib
import time
import logging
import argparse
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('file_monitor.log'),
        logging.StreamHandler()
    ]
)

class FileIntegrityHandler(FileSystemEventHandler):
    def __init__(self, baseline_file):
        self.baseline_file = baseline_file
        self.baseline = self._load_baseline()

    def _load_baseline(self):
        if os.path.exists(self.baseline_file):
            with open(self.baseline_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_baseline(self):
        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline, f, indent=4)

    def _calculate_file_hash(self, filepath):
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _get_file_metadata(self, filepath):
        stat = os.stat(filepath)
        return {
            'size': stat.st_size,
            'modified_time': stat.st_mtime,
            'created_time': stat.st_ctime,
            'permissions': oct(stat.st_mode)[-3:],
            'hash': self._calculate_file_hash(filepath)
        }

    def on_modified(self, event):
        if not event.is_directory:
            filepath = event.src_path
            logging.info(f"File modified: {filepath}")
            self._check_integrity(filepath)

    def on_created(self, event):
        if not event.is_directory:
            filepath = event.src_path
            logging.info(f"File created: {filepath}")
            self._check_integrity(filepath)

    def on_deleted(self, event):
        if not event.is_directory:
            filepath = event.src_path
            logging.info(f"File deleted: {filepath}")
            if filepath in self.baseline:
                del self.baseline[filepath]
                self._save_baseline()

    def _check_integrity(self, filepath):
        try:
            current_metadata = self._get_file_metadata(filepath)
            
            if filepath in self.baseline:
                old_metadata = self.baseline[filepath]
                if current_metadata['hash'] != old_metadata['hash']:
                    logging.warning(f"File integrity check failed for {filepath}")
                    logging.warning(f"Old hash: {old_metadata['hash']}")
                    logging.warning(f"New hash: {current_metadata['hash']}")
            
            self.baseline[filepath] = current_metadata
            self._save_baseline()
            
        except Exception as e:
            logging.error(f"Error checking file {filepath}: {str(e)}")

def scan_directory(directory_path, baseline_file):
    """Scan directory and create baseline of file metadata and hashes."""
    handler = FileIntegrityHandler(baseline_file)
    baseline = {}
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                baseline[filepath] = handler._get_file_metadata(filepath)
                logging.info(f"Scanned: {filepath}")
            except Exception as e:
                logging.error(f"Error scanning {filepath}: {str(e)}")
    
    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=4)
    
    logging.info(f"Baseline created with {len(baseline)} files")

def compare_with_baseline(directory_path, baseline_file):
    """Compare current state with baseline."""
    handler = FileIntegrityHandler(baseline_file)
    baseline = handler.baseline
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                current_metadata = handler._get_file_metadata(filepath)
                
                if filepath not in baseline:
                    logging.warning(f"New file detected: {filepath}")
                elif current_metadata['hash'] != baseline[filepath]['hash']:
                    logging.warning(f"File modified: {filepath}")
                    logging.warning(f"Old hash: {baseline[filepath]['hash']}")
                    logging.warning(f"New hash: {current_metadata['hash']}")
                
            except Exception as e:
                logging.error(f"Error comparing {filepath}: {str(e)}")
    
    # Check for deleted files
    for filepath in baseline:
        if not os.path.exists(filepath):
            logging.warning(f"File deleted: {filepath}")

def watch_directory(directory_path, baseline_file):
    """Watch directory for changes in real-time."""
    handler = FileIntegrityHandler(baseline_file)
    observer = Observer()
    observer.schedule(handler, path=directory_path, recursive=True)
    observer.start()
    
    logging.info(f"Watching directory: {directory_path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Monitoring stopped")
    observer.join()

def main():
    parser = argparse.ArgumentParser(description='File Integrity Monitoring System')
    parser.add_argument('directory', help='Directory to monitor')
    parser.add_argument('--baseline', default='baseline.json', help='Baseline file path')
    parser.add_argument('--mode', choices=['scan', 'compare', 'watch'], required=True,
                      help='Operation mode: scan, compare, or watch')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        logging.error(f"Directory not found: {args.directory}")
        return
    
    if args.mode == 'scan':
        scan_directory(args.directory, args.baseline)
    elif args.mode == 'compare':
        compare_with_baseline(args.directory, args.baseline)
    elif args.mode == 'watch':
        watch_directory(args.directory, args.baseline)

if __name__ == "__main__":
    main() 



#create baseline python file_integrity_monitor.py /path/to/directory --mode scan
#python file_integrity_monitor.py /path/to/directory --mode compare
#python file_integrity_monitor.py /path/to/directory --mode watch
