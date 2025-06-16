import pandas as pd

url = "https://urlhaus.abuse.ch/downloads/csv/"
df = pd.read_csv(url, comment="#", encoding="utf-8")

# Filter recent malware URLs
malicious = df[df['threat'].notnull()][['dateadded', 'url', 'threat']]
print(malicious.head())
