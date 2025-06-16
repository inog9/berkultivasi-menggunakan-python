import requests

# Your SentinelOne API token and site URL
API_TOKEN = "your_sentinelone_token"
SITE_URL  = "https://usea1-partners.sentinelone.net/web/api/v2.1"

def sentinel_request(endpoint, params=None, method='GET', body=None):
    """
    Helper function to call SentinelOne API endpoints.
    """
    url = f"{SITE_URL}/{endpoint}"
    headers = {
        'Authorization': f"APIToken {API_TOKEN}",
        'Content-Type': 'application/json'
    }
    if method == 'GET':
        resp = requests.get(url, headers=headers, params=params)
    elif method == 'POST':
        resp = requests.post(url, headers=headers, json=body)
    else:
        raise ValueError("Unsupported HTTP method")

    resp.raise_for_status()
    return resp.json()

# Test connectivity
resp = sentinel_request("agents")
print(f"Total agents: {resp.get('data', {}).get('totalCount')}")
