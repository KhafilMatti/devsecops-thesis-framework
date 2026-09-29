import json
from pathlib import Path


RAW_FILE = Path("data/dependabot_alerts_raw.json")
OUTPUT_FILE = Path("data/normalised_events.json")


def normalise_dependabot_alert(alert):
    advisory = alert.get("security_advisory", {})
    dependency = alert.get("dependency", {})
    package = dependency.get("package", {})

    cvss = advisory.get("cvss", {})
    vulnerabilities = alert.get("security_vulnerability", {})

    return {
        "event_id": f"github-dependabot-{alert.get('number')}",
        "source_platform": "GitHub",
        "source_tool": "Dependabot",
        "event_type": "dependency_vulnerability",

        "title": advisory.get("summary"),
        "description": advisory.get("description"),
        "severity": advisory.get("severity"),
        "cve_id": advisory.get("cve_id"),
        "ghsa_id": advisory.get("ghsa_id"),

        "package_name": package.get("name"),
        "package_ecosystem": package.get("ecosystem"),
        "manifest_path": dependency.get("manifest_path"),

        "vulnerable_version_range": vulnerabilities.get("vulnerable_version_range"),
        "patched_version": vulnerabilities.get("first_patched_version", {}).get("identifier")
        if vulnerabilities.get("first_patched_version") else None,

        "cvss_score": cvss.get("score"),
        "cvss_vector": cvss.get("vector_string"),

        "state": alert.get("state"),
        "created_at": alert.get("created_at"),
        "fixed_at": alert.get("fixed_at"),
        "dismissed_at": alert.get("dismissed_at"),

        "raw_url": alert.get("html_url")
    }


def main():
    if not RAW_FILE.exists():
        raise FileNotFoundError(
            "Raw Dependabot alerts file not found. Run fetch_dependabot_alerts.py first."
        )

    with open(RAW_FILE, "r", encoding="utf-8") as file:
        raw_alerts = json.load(file)

    normalised_events = [
        normalise_dependabot_alert(alert)
        for alert in raw_alerts
    ]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(normalised_events, file, indent=4)

    print(f"Normalised {len(normalised_events)} events")
    print(f"Saved output to {OUTPUT_FILE}")

    for event in normalised_events:
        print("-" * 60)
        print("Event ID:", event["event_id"])
        print("Title:", event["title"])
        print("Severity:", event["severity"])
        print("CVE:", event["cve_id"])
        print("Package:", event["package_name"])
        print("CVSS:", event["cvss_score"])


if __name__ == "__main__":
    main()