import json
from pathlib import Path
from statistics import mean
from typing import Any

BASELINE_FILE = Path("data/baseline_ranked_events.json")
PROPOSED_FILE = Path("data/proposed_ranked_events.json")
OUTPUT_FILE = Path("data/ranking_comparison.json")


def load_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a list.")

    return data


def main() -> None:
    baseline_events = load_json(BASELINE_FILE)
    proposed_events = load_json(PROPOSED_FILE)

    baseline_by_id = {
        event["event_id"]: event
        for event in baseline_events
    }

    proposed_by_id = {
        event["event_id"]: event
        for event in proposed_events
    }

    shared_ids = sorted(
        set(baseline_by_id) & set(proposed_by_id)
    )

    comparison_rows = []

    for event_id in shared_ids:
        baseline = baseline_by_id[event_id]
        proposed = proposed_by_id[event_id]

        baseline_rank = int(baseline["baseline_rank"])
        proposed_rank = int(proposed["proposed_rank"])

        rank_change = baseline_rank - proposed_rank

        comparison_rows.append(
            {
                "event_id": event_id,
                "source_platform": proposed.get("source_platform"),
                "source_tool": proposed.get("source_tool"),
                "cve_id": proposed.get("cve_id"),
                "severity": proposed.get("severity"),
                "cvss_score": proposed.get("cvss_score"),
                "risk_score": proposed.get("risk_score"),
                "priority_level": proposed.get("priority_level"),
                "baseline_rank": baseline_rank,
                "proposed_rank": proposed_rank,
                "rank_change": rank_change,
            }
        )

    comparison_rows.sort(
        key=lambda row: abs(row["rank_change"]),
        reverse=True,
    )

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(comparison_rows, file, indent=4)

    moved_events = [
        row for row in comparison_rows
        if row["rank_change"] != 0
    ]

    promoted_events = [
        row for row in comparison_rows
        if row["rank_change"] > 0
    ]

    demoted_events = [
        row for row in comparison_rows
        if row["rank_change"] < 0
    ]

    average_change = (
        mean(abs(row["rank_change"]) for row in comparison_rows)
        if comparison_rows
        else 0
    )

    print(f"Events compared: {len(comparison_rows)}")
    print(f"Events whose rank changed: {len(moved_events)}")
    print(f"Events promoted by the proposed model: {len(promoted_events)}")
    print(f"Events demoted by the proposed model: {len(demoted_events)}")
    print(f"Mean absolute rank change: {average_change:.2f}")
    print(f"Saved output to {OUTPUT_FILE}")

    print("\nLargest ranking differences:")

    for row in comparison_rows[:10]:
        print("-" * 70)
        print("Event:", row["event_id"])
        print("CVE:", row["cve_id"])
        print("Platform:", row["source_platform"])
        print("Baseline rank:", row["baseline_rank"])
        print("Proposed rank:", row["proposed_rank"])
        print("Rank change:", row["rank_change"])
        print("Risk score:", row["risk_score"])


if __name__ == "__main__":
    main()