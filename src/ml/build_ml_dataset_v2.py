import csv
import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
        PROJECT_ROOT
        / "data"
        / "ml"
        / "ml_training_dataset_v2.json"
)

OUTPUT_FILE = (
        PROJECT_ROOT
        / "data"
        / "ml"
        / "ml_training_features_v2.csv"
)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def normalise_priority(priority: str | None) -> str:
    if not priority:
        return "UNKNOWN"

    for label in ("P1", "P2", "P3", "P4"):
        if priority.startswith(label):
            return label

    return "UNKNOWN"


def bool_to_int(value: Any) -> int:
    return 1 if value is True else 0


def extract_features(event: dict[str, Any]) -> dict[str, Any]:

    context = event.get("asset_context", {}) or {}

    stride = event.get("stride_categories", []) or []

    return {
        # Identity — retained for group-aware splitting
        "event_id": event.get("event_id", ""),
        "seed_event_id": event.get("seed_event_id", ""),

        # Scanner/security characteristics
        "cvss_score": float(
            event.get("cvss_score") or 0
        ),
        "severity": event.get(
            "severity",
            "unknown",
        ),
        "event_type": event.get(
            "event_type",
            "unknown",
        ),
        "source_platform": event.get(
            "source_platform",
            "unknown",
        ),
        "package_ecosystem": event.get(
            "package_ecosystem",
            "unknown",
        ),

        # Context characteristics
        "environment": context.get(
            "environment",
            "unknown",
        ),
        "internet_facing": bool_to_int(
            context.get("internet_facing")
        ),
        "runtime_reachable": bool_to_int(
            context.get("runtime_reachable")
        ),
        "business_criticality": context.get(
            "business_criticality",
            "unknown",
        ),
        "deployment_stage": context.get(
            "deployment_stage",
            "unknown",
        ),
        "data_sensitivity": context.get(
            "data_sensitivity",
            "unknown",
        ),
        "safety_impact": context.get(
            "safety_impact",
            "unknown",
        ),
        "operational_disruption": context.get(
            "operational_disruption",
            "unknown",
        ),
        "financial_loss": context.get(
            "financial_loss",
            "unknown",
        ),
        "regulatory_exposure": context.get(
            "regulatory_exposure",
            "unknown",
        ),
        "reputational_damage": context.get(
            "reputational_damage",
            "unknown",
        ),



        # STRIDE features
        "stride_spoofing": int(
            "Spoofing" in stride
        ),
        "stride_tampering": int(
            "Tampering" in stride
        ),
        "stride_repudiation": int(
            "Repudiation" in stride
        ),
        "stride_information_disclosure": int(
            "Information Disclosure" in stride
        ),
        "stride_denial_of_service": int(
            "Denial of Service" in stride
        ),
        "stride_elevation_of_privilege": int(
            "Elevation of Privilege" in stride
        ),

        # Remediation characteristics
        "patch_available": bool_to_int(
            event.get("recommendation", {}).get(
                "patch_available"
            )
        ),

        # TARGET
        "priority": normalise_priority(
            event.get("priority_level")
        ),
    }


def main() -> None:

    events = load_json(INPUT_FILE)

    if not isinstance(events, list):
        raise ValueError(
            "ML training dataset must contain a JSON list."
        )

    rows = [
        extract_features(event)
        for event in events
    ]

    if not rows:
        raise ValueError(
            "No training records were found."
        )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
            "w",
            encoding="utf-8",
            newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=list(rows[0].keys()),
        )

        writer.writeheader()
        writer.writerows(rows)

    print("ML feature dataset created successfully.")
    print(f"Input scenarios: {len(events)}")
    print(f"Output rows: {len(rows)}")
    print(f"Features/columns: {len(rows[0])}")
    print(f"Saved to: {OUTPUT_FILE}")

    seeds = {
        row["seed_event_id"]
        for row in rows
    }

    print(f"Unique seed events: {len(seeds)}")

    priorities: dict[str, int] = {}

    for row in rows:
        priority = row["priority"]

        priorities[priority] = (
                priorities.get(priority, 0) + 1
        )

    print("\nPriority distribution:")

    for priority in sorted(priorities):
        print(
            f"  {priority}: "
            f"{priorities[priority]}"
        )


if __name__ == "__main__":
    main()