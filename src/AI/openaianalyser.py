import json
import os
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

INPUT_FILE = Path("data/enriched_events.json")
OUTPUT_FILE = Path("data/ai_analysis_results.json")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def create_analysis_prompt(event):
    return f"""
You are a senior DevSecOps cybersecurity analyst.

Analyse the following CI/CD security event and determine how important it is.

Event:
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

Return your answer in this exact structure:

Risk Importance:
Priority Assessment:
STRIDE Justification:
Security Impact:
Recommended Action:
Analyst Summary:
""".strip()


def analyse_event(event):
    prompt = create_analysis_prompt(event)

    response = client.responses.create(
        model="gpt-4o-mini",
        input=prompt
    )

    return {
        "event_id": event.get("event_id"),
        "title": event.get("title"),
        "cve_id": event.get("cve_id"),
        "risk_score": event.get("risk_score"),
        "priority_level": event.get("priority_level"),
        "ai_analysis": response.output_text
    }


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            "enriched_events.json not found. Run risk enrichment first."
        )

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        events = json.load(file)

    results = []

    for event in events:
        print(f"Analysing {event.get('event_id')} - {event.get('title')}")
        result = analyse_event(event)
        results.append(result)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print(f"Saved AI analysis for {len(results)} events to {OUTPUT_FILE}")

    print("\nSample AI analysis:")
    print("-" * 60)
    print(results[0]["ai_analysis"])


if __name__ == "__main__":
    main()