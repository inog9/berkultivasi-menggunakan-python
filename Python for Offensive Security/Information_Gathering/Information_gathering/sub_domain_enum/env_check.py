#!/usr/bin/env python3
"""
env_check.py – Verifies tool versions, raw-socket capability and
Python backlog limits so you don't find out mid-scan that masscan
drops to 300 pps or that the kernel is killing async sockets.
"""
import shutil, os, subprocess, sys, resource

# ---- 1. Binaries ----------------------------------------------------------
need = ["masscan", "nmap", "openssl"]        # tls-scan optional
for bin in need:
    if not shutil.which(bin):
        sys.exit(f"[-] Missing binary: {bin}")

# ---- 2. Raw-socket privilege (Linux only) ---------------------------------
if os.geteuid() != 0:
    try:
        subprocess.check_call(["masscan", "--ping", "-p0-0", "127.0.0.1"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        sys.exit("[-] masscan cannot open raw sockets – run as root or set CAP_NET_RAW")

# ---- 3. File-descriptor limit --------------------------------------------
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
print(f"[i] open-file limit: {soft}/{hard}")
if soft < 4096:
    print("[!] Consider `ulimit -n 8192` for high-concurrency scans.")

# ---- 4. Python version & libs --------------------------------------------
req = {"trio": "0.24", "httpx": "0.27", "asyncssh": "2.14"}
for mod, ver in req.items():
    try:
        m = __import__(mod)
        from packaging.version import parse
        if parse(m.__version__) < parse(ver):
            print(f"[!] {mod} {m.__version__} < required {ver}")
    except ImportError:
        sys.exit(f"[-] missing pip package {mod}")

print("[+] Environment looks good.")
