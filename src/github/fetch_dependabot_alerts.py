import os
import json
import requests
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OWNER = os.getenv("GITHUB_OWNER")
REPO = os.getenv("GITHUB_REPO")

if not GITHUB_TOKEN or not OWNER or not REPO:
    raise ValueError("Missing GITHUB_TOKEN, GITHUB_OWNER, or GITHUB_REPO in .env file")

url = f"https://api.github.com/repos/{OWNER}/{REPO}/dependabot/alerts"

headers = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

params = {
    "state": "open",
    "per_page": 100
}

response = requests.get(url, headers=headers, params=params)

if response.status_code != 200:
    print("GitHub API request failed")
    print("Status code:", response.status_code)
    print("Response:", response.text)
    raise SystemExit

alerts = response.json()

Path("data").mkdir(exist_ok=True)

with open("data/dependabot_alerts_raw.json", "w", encoding="utf-8") as file:
    json.dump(alerts, file, indent=4)

print(f"Saved {len(alerts)} Dependabot alerts to data/dependabot_alerts_raw.json")

for alert in alerts:
    advisory = alert.get("security_advisory", {})
    dependency = alert.get("dependency", {})
    package = dependency.get("package", {})

    print("-" * 60)
    print("Alert number:", alert.get("number"))
    print("State:", alert.get("state"))
    print("Package:", package.get("name"))
    print("Ecosystem:", package.get("ecosystem"))
    print("Severity:", advisory.get("severity"))
    print("CVE:", advisory.get("cve_id"))
    print("Summary:", advisory.get("summary"))