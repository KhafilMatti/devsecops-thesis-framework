import copy

import json
import random
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SRC_DIR = PROJECT_ROOT / "src"
ANALYSIS_DIR = SRC_DIR / "analysis"

# Make both src/ and src/analysis available for imports.
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

if str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))

from analysis.riskenrichment import enrich_event  # noqa: E402

INPUT_FILE = PROJECT_ROOT / "data" / "all_normalised_events.json"
CONTEXT_FILE = PROJECT_ROOT / "data" / "asset_context.json"
CONTEXT_RULES_FILE = PROJECT_ROOT / "data" / "asset_context_rules.json"

OUTPUT_DIR = PROJECT_ROOT / "data" / "ml"
OUTPUT_FILE = OUTPUT_DIR / "ml_training_dataset.json"

NUMBER_OF_SCENARIOS = 3000
RANDOM_SEED = 42


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


def generate_variant(
        base_event: dict[str, Any],
        scenario_number: int,
) -> dict[str, Any]:
    """
    Create a controlled variation of an existing security event.

    We vary selected event characteristics while allowing the existing
    XAI framework to derive context and priority.
    """
    event = copy.deepcopy(base_event)

    original_event_id = base_event.get(
        "event_id",
        "unknown",
    )

    event["seed_event_id"] = original_event_id

    event["event_id"] = (
        f"ml-scenario-{scenario_number}-"
        f"{original_event_id}"
    )

    # Controlled CVSS variation
    original_cvss = float(event.get("cvss_score") or 0)

    cvss_change = random.uniform(-2.5, 1.0)

    event["cvss_score"] = round(
        max(0.0, min(10.0, original_cvss + cvss_change)),
        1,
    )

    # Keep severity broadly consistent with the altered CVSS.
    cvss = event["cvss_score"]

    if cvss >= 9.0:
        event["severity"] = "critical"
    elif cvss >= 7.0:
        event["severity"] = "high"
    elif cvss >= 4.0:
        event["severity"] = "medium"
    else:
        event["severity"] = "low"

    return event


def main() -> None:
    random.seed(RANDOM_SEED)

    events = load_json(INPUT_FILE)
    context_profiles = load_json(CONTEXT_FILE)
    context_rules = load_json(CONTEXT_RULES_FILE)

    if not isinstance(events, list):
        raise ValueError("Input events must be a JSON list.")

    generated_events: list[dict[str, Any]] = []

    for scenario_number in range(NUMBER_OF_SCENARIOS):
        base_event = random.choice(events)

        variant = generate_variant(
            base_event=base_event,
            scenario_number=scenario_number,
        )

        enriched = enrich_event(
            event=variant,
            context_profiles=context_profiles,
            context_rules=context_rules,
        )

        generated_events.append(enriched)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(
            generated_events,
            file,
            indent=2,
        )

    print("Training scenario generation completed.")
    print(f"Base events: {len(events)}")
    print(f"Generated scenarios: {len(generated_events)}")
    print(f"Saved to: {OUTPUT_FILE}")

    distribution: dict[str, int] = {}

    for event in generated_events:
        priority = normalise_priority(
            event.get("priority_level")
        )

        distribution[priority] = (
                distribution.get(priority, 0) + 1
        )

    print("\nPriority distribution:")

    for priority in sorted(distribution):
        print(
            f"  {priority}: "
            f"{distribution[priority]}"
        )


if __name__ == "__main__":
    main()