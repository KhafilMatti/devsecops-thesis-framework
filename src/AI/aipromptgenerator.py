import json
from pathlib import Path

INPUT_FILE = Path("data/enriched_events.json")
OUTPUT_FILE = Path("data/ai_prompts.json")


def create_prompt(event):
    return f"""
You are a senior cybersecurity analyst.

Analyse the following DevSecOps CI/CD security event.

Event Details:
- Event ID: {event.get("event_id")}
- Source Platform: {event.get("source_platform")}
- Source Tool: {event.get("source_tool")}
- Event Type: {event.get("event_type")}
- Title: {event.get("title")}
- Severity: {event.get("severity")}
- CVE ID: {event.get("cve_id")}
- Package: {event.get("package_name")}
- Ecosystem: {event.get("package_ecosystem")}
- CVSS Score: {event.get("cvss_score")}
- STRIDE Categories: {", ".join(event.get("stride_categories", []))}
- Current Risk Score: {event.get("risk_score")}
- Current Priority Level: {event.get("priority_level")}

Please provide:
1. A short explanation of how serious this event is.
2. Whether the priority level is appropriate.
3. The likely security impact.
4. The STRIDE category justification.
5. Recommended remediation action.
6. A concise analyst-friendly summary.

Return the answer in clear bullet points.
""".strip()


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            "enriched_events.json not found. Run risk enrichment first."
        )

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        events = json.load(file)

    prompts = []

    for event in events:
        prompts.append({
            "event_id": event.get("event_id"),
            "title": event.get("title"),
            "prompt": create_prompt(event)
        })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(prompts, file, indent=4)

    print(f"Generated {len(prompts)} AI prompts")
    print(f"Saved output to {OUTPUT_FILE}")

    print("\nSample prompt:")
    print("-" * 60)
    print(prompts[0]["prompt"])


if __name__ == "__main__":
    main()