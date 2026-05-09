import urllib.request
import json

url = "http://localhost:8000/api/v1/scans/"
data = json.dumps({"repo_url": "https://github.com/OWASP/NodeGoat"}).encode("utf-8")
headers = {"Content-Type": "application/json"}
req = urllib.request.Request(url, data=data, headers=headers, method="POST")

try:
    with urllib.request.urlopen(req) as response:
        print("Status:", response.status)
        print("Response:", response.read().decode("utf-8"))
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code)
    print("Response:", e.read().decode("utf-8"))
except Exception as e:
    print("Error:", e)
