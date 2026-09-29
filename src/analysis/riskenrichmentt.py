import json
from pathlib import Path

INPUT_FILE = Path("data/all_normalised_events.json")
OUTPUT_FILE = Path("data/enriched_events.json")


SEVERITY_SCORES = {
    "critical": 40,
    "high": 30,
    "moderate": 20,
    "medium": 20,
    "low": 10,
    None: 0
}


def map_stride(event):
    title = (event.get("title") or "").lower()
    description = (event.get("description") or "").lower()
    text = title + " " + description

    stride = []

    if "remote code" in text or "code execution" in text or "injection" in text:
        stride.extend(["Tampering", "Elevation of Privilege"])

    if "information disclosure" in text or "leak" in text or "exposure" in text:
        stride.append("Information Disclosure")

    if "denial of service" in text or "dos" in text or "availability" in text:
        stride.append("Denial of Service")

    if "authentication" in text or "bypass" in text or "privilege" in text:
        stride.extend(["Spoofing", "Elevation of Privilege"])

    if not stride:
        stride.append("Unclassified")

    return list(set(stride))


def calculate_priority_score(event, stride_categories):
    severity = (event.get("severity") or "").lower()
    cvss_score = event.get("cvss_score") or 0
    patched_version = event.get("patched_version")

    score = 0

    # Severity weighting
    score += SEVERITY_SCORES.get(severity, 0)

    # CVSS weighting
    if cvss_score >= 9:
        score += 25
    elif cvss_score >= 7:
        score += 18
    elif cvss_score >= 4:
        score += 10
    elif cvss_score > 0:
        score += 5

    # Patch availability
    if patched_version:
        score += 10

    # STRIDE impact weighting
    high_impact_stride = {
        "Elevation of Privilege",
        "Tampering",
        "Information Disclosure",
        "Denial of Service"
    }

    score += min(
        20,
        len(set(stride_categories).intersection(high_impact_stride)) * 5
    )

    # Runtime dependency / package vulnerability boost
    if event.get("event_type") == "dependency_vulnerability":
        score += 5

    return min(score, 100)


def assign_priority_level(score):
    if score >= 85:
        return "P1 - Immediate"
    elif score >= 70:
        return "P2 - High"
    elif score >= 50:
        return "P3 - Medium"
    return "P4 - Low"


def generate_explanation(event, score, priority, stride_categories):
    reasons = []

    severity = event.get("severity")
    cvss = event.get("cvss_score")
    patched = event.get("patched_version")

    if severity:
        reasons.append(f"The event has a {severity} severity rating.")

    if cvss:
        reasons.append(f"The vulnerability has a CVSS score of {cvss}.")

    if patched:
        reasons.append(
            f"A patched version is available ({patched}), so remediation is actionable."
        )

    if "Elevation of Privilege" in stride_categories:
        reasons.append(
            "The event maps to Elevation of Privilege, meaning successful exploitation may increase attacker control."
        )

    if "Tampering" in stride_categories:
        reasons.append(
            "The event maps to Tampering, meaning exploitation may allow modification of application behaviour or data."
        )

    if "Information Disclosure" in stride_categories:
        reasons.append(
            "The event maps to Information Disclosure, meaning sensitive information could be exposed."
        )

    if "Denial of Service" in stride_categories:
        reasons.append(
            "The event maps to Denial of Service, meaning exploitation may affect availability."
        )

    if event.get("event_type") == "dependency_vulnerability":
        reasons.append(
            "The event affects a dependency in the software supply chain, making it relevant to CI/CD security."
        )

    return {
        "summary": f"This event was assigned {priority} with a risk score of {score}/100.",
        "reasons": reasons
    }


def enrich_event(event):
    stride_categories = map_stride(event)
    score = calculate_priority_score(event, stride_categories)
    priority = assign_priority_level(score)
    explanation = generate_explanation(event, score, priority, stride_categories)

    enriched_event = event.copy()
    enriched_event["stride_categories"] = stride_categories
    enriched_event["risk_score"] = score
    enriched_event["priority_level"] = priority
    enriched_event["explanation"] = explanation

    return enriched_event


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            "normalised_events.json not found. Run normaliseevents.py first."
        )

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        events = json.load(file)

    enriched_events = [enrich_event(event) for event in events]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(enriched_events, file, indent=4)

    print(f"Enriched {len(enriched_events)} events")
    print(f"Saved output to {OUTPUT_FILE}")

    for event in enriched_events:
        print("-" * 60)
        print("Event ID:", event["event_id"])
        print("Title:", event["title"])
        print("Severity:", event["severity"])
        print("CVE:", event["cve_id"])
        print("CVSS:", event["cvss_score"])
        print("STRIDE:", ", ".join(event["stride_categories"]))
        print("Risk Score:", event["risk_score"])
        print("Priority:", event["priority_level"])
        print("Explanation:", event["explanation"]["summary"])


if __name__ == "__main__":
    main()