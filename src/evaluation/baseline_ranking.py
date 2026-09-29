import json
from pathlib import Path
from typing import Any

INPUT_FILE = Path("data/all_normalised_events.json")
OUTPUT_FILE = Path("data/baseline_ranked_events.json")

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "moderate": 2,
    "low": 1,
    "unknown": 0,
}


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


def baseline_sort_key(event: dict[str, Any]) -> tuple[int, float]:
    severity = str(event.get("severity", "unknown")).lower()
    severity_weight = SEVERITY_ORDER.get(severity, 0)

    try:
        cvss_score = float(event.get("cvss_score") or 0)
    except (TypeError, ValueError):
        cvss_score = 0.0

    return severity_weight, cvss_score


def main() -> None:
    events = load_events()

    ranked_events = sorted(
        events,
        key=baseline_sort_key,
        reverse=True,
    )

    for rank, event in enumerate(ranked_events, start=1):
        event["baseline_rank"] = rank
        event["baseline_method"] = "severity_then_cvss"

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(ranked_events, file, indent=4)

    print(f"Baseline-ranked events: {len(ranked_events)}")
    print(f"Saved output to {OUTPUT_FILE}")

    print("\nTop baseline-ranked events:")

    for event in ranked_events[:10]:
        print("-" * 70)
        print("Rank:", event["baseline_rank"])
        print("Event ID:", event.get("event_id"))
        print("Platform:", event.get("source_platform"))
        print("CVE:", event.get("cve_id"))
        print("Severity:", event.get("severity"))
        print("CVSS:", event.get("cvss_score"))


if __name__ == "__main__":
    main()