from taxii2client.v21 import Server

# Connect to a public TAXII server
server = Server("https://cti.taxii.org/taxii/")

# List API roots
api_root = server.api_roots[0]  # Usually default API root

# Discover collections
collections = api_root.collections
print("[+] Available Collections:")
for coll in collections:
    print(f"  - {coll.title}")

# Pull a bundle of objects from a collection
collection = collections[0]
objects = collection.get_objects()
for obj in objects['objects']:
    if obj['type'] == 'indicator':
        print(f"[!] Indicator: {obj['pattern']} (Labels: {obj['labels']})")
