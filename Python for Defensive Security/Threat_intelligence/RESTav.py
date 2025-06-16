import requests

API_KEY = "your_otx_api_key"
headers = {"X-OTX-API-KEY": API_KEY}

r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed", headers=headers)

if r.status_code == 200:
    data = r.json()
    for pulse in data["results"]:
        print(f"[+] Pulse: {pulse['name']}")
        for indicator in pulse['indicators']:
            print(f"    → {indicator['type']}: {indicator['indicator']}")
else:
    print("Failed to fetch OTX pulses.")
