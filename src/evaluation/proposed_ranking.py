import json
from pathlib import Path
from typing import Any

INPUT_FILE = Path("data/enriched_events.json")
OUTPUT_FILE = Path("data/proposed_ranked_events.json")


def load_events() -> list[dict[str, Any]]:
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Input file must contain a JSON list.")

    return events


def proposed_sort_key(event: dict[str, Any]) -> tuple[float, float]:
    try:
        risk_score = float(event.get("risk_score") or 0)
    except (TypeError, ValueError):
        risk_score = 0.0

    try:
        cvss_score = float(event.get("cvss_score") or 0)
    except (TypeError, ValueError):
        cvss_score = 0.0

    return risk_score, cvss_score


def main() -> None:
    events = load_events()

    ranked_events = sorted(
        events,
        key=proposed_sort_key,
        reverse=True,
    )

    for rank, event in enumerate(ranked_events, start=1):
        event["proposed_rank"] = rank
        event["ranking_method"] = "context_aware_risk_score"

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(ranked_events, file, indent=4)

    print(f"Proposed-model ranked events: {len(ranked_events)}")
    print(f"Saved output to {OUTPUT_FILE}")

    print("\nTop proposed-model events:")

    for event in ranked_events[:10]:
        print("-" * 70)
        print("Rank:", event["proposed_rank"])
        print("Event ID:", event.get("event_id"))
        print("Platform:", event.get("source_platform"))
        print("CVE:", event.get("cve_id"))
        print("Severity:", event.get("severity"))
        print("CVSS:", event.get("cvss_score"))
        print("Risk score:", event.get("risk_score"))
        print("Priority:", event.get("priority_level"))


if __name__ == "__main__":
    main()