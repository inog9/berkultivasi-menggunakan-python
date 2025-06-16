import requests

# Replace these with your CrowdStrike API credentials
CLIENT_ID     = "your_client_id"
CLIENT_SECRET = "your_client_secret"
OAUTH_URL     = "https://api.crowdstrike.com/oauth2/token"

def get_falcon_token(client_id, client_secret):
    """
    Obtain an OAuth2 token from CrowdStrike Falcon.
    """
    data = {
        'client_id': client_id,
        'client_secret': client_secret
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(OAUTH_URL, data=data, headers=headers)
    response.raise_for_status()  # Raise on HTTP error
    token = response.json().get('access_token')
    return token

token = get_falcon_token(CLIENT_ID, CLIENT_SECRET)
print("Access token acquired.")
