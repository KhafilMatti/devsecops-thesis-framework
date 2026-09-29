import copy
import json
import random
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SRC_DIR = PROJECT_ROOT / "src"
ANALYSIS_DIR = SRC_DIR / "analysis"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

if str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))

from analysis.riskenrichment import enrich_event  # noqa: E402


INPUT_FILE = PROJECT_ROOT / "data" / "all_normalised_events.json"

OUTPUT_DIR = PROJECT_ROOT / "data" / "ml"
OUTPUT_FILE = OUTPUT_DIR / "ml_training_dataset_v2.json"

NUMBER_OF_SCENARIOS = 5000
RANDOM_SEED = 42


# ---------------------------------------------------------------------
# Controlled context profiles
# ---------------------------------------------------------------------

CONTEXT_PROFILES = {
    "development_internal": {
        "environment": "development",
        "internet_facing": False,
        "runtime_reachable": False,
        "business_criticality": "low",
        "deployment_stage": "build",
        "data_sensitivity": "low",
        "safety_impact": "low",
        "operational_disruption": "low",
        "financial_loss": "low",
        "regulatory_exposure": "low",
        "reputational_damage": "low",
    },

    "development_runtime": {
        "environment": "development",
        "internet_facing": False,
        "runtime_reachable": True,
        "business_criticality": "medium",
        "deployment_stage": "runtime",
        "data_sensitivity": "medium",
        "safety_impact": "low",
        "operational_disruption": "medium",
        "financial_loss": "low",
        "regulatory_exposure": "low",
        "reputational_damage": "low",
    },

    "production_internal": {
        "environment": "production",
        "internet_facing": False,
        "runtime_reachable": True,
        "business_criticality": "high",
        "deployment_stage": "runtime",
        "data_sensitivity": "high",
        "safety_impact": "medium",
        "operational_disruption": "high",
        "financial_loss": "high",
        "regulatory_exposure": "medium",
        "reputational_damage": "medium",
    },

    "production_external": {
        "environment": "production",
        "internet_facing": True,
        "runtime_reachable": True,
        "business_criticality": "high",
        "deployment_stage": "runtime",
        "data_sensitivity": "high",
        "safety_impact": "high",
        "operational_disruption": "high",
        "financial_loss": "high",
        "regulatory_exposure": "high",
        "reputational_damage": "high",
    },

    "production_build": {
        "environment": "production",
        "internet_facing": False,
        "runtime_reachable": False,
        "business_criticality": "medium",
        "deployment_stage": "build",
        "data_sensitivity": "medium",
        "safety_impact": "low",
        "operational_disruption": "medium",
        "financial_loss": "medium",
        "regulatory_exposure": "medium",
        "reputational_damage": "medium",
    },

    "healthcare_runtime": {
        "environment": "production",
        "internet_facing": True,
        "runtime_reachable": True,
        "business_criticality": "critical",
        "deployment_stage": "runtime",
        "data_sensitivity": "critical",
        "safety_impact": "high",
        "operational_disruption": "high",
        "financial_loss": "medium",
        "regulatory_exposure": "high",
        "reputational_damage": "high",
    },

    "financial_runtime": {
        "environment": "production",
        "internet_facing": True,
        "runtime_reachable": True,
        "business_criticality": "critical",
        "deployment_stage": "runtime",
        "data_sensitivity": "critical",
        "safety_impact": "medium",
        "operational_disruption": "high",
        "financial_loss": "high",
        "regulatory_exposure": "high",
        "reputational_damage": "high",
    },
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def adjust_cvss_and_severity(
        event: dict[str, Any],
) -> None:
    """
    Produce controlled technical variation without completely
    changing the identity of the original vulnerability.
    """

    original_cvss = float(
        event.get("cvss_score") or 0
    )

    change = random.uniform(-2.0, 0.75)

    new_cvss = round(
        max(
            0.0,
            min(
                10.0,
                original_cvss + change,
                ),
        ),
        1,
    )

    event["cvss_score"] = new_cvss

    if new_cvss >= 9.0:
        event["severity"] = "critical"

    elif new_cvss >= 7.0:
        event["severity"] = "high"

    elif new_cvss >= 4.0:
        event["severity"] = "medium"

    else:
        event["severity"] = "low"


def create_scenario(
        base_event: dict[str, Any],
        scenario_number: int,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:
    """
    Create one controlled security scenario.

    Returns:
        event
        scenario-specific context profiles
    """

    event = copy.deepcopy(base_event)

    seed_event_id = base_event.get(
        "event_id",
        "unknown",
    )

    profile_name = random.choice(
        list(CONTEXT_PROFILES.keys())
    )

    selected_context = copy.deepcopy(
        CONTEXT_PROFILES[profile_name]
    )

    # Unique asset path for this scenario.
    synthetic_path = (
        f"ml/v2/"
        f"{profile_name}/"
        f"scenario-{scenario_number}"
    )

    event["seed_event_id"] = seed_event_id

    event["event_id"] = (
        f"ml-v2-{scenario_number}-"
        f"{seed_event_id}"
    )

    # The resolver uses asset paths to find static profiles.
    event["manifest_path"] = synthetic_path

    adjust_cvss_and_severity(event)

    # Build an isolated context configuration for this scenario.
    scenario_profiles = {
        "default": CONTEXT_PROFILES[
            "development_internal"
        ],
        synthetic_path: selected_context,
    }

    # Store metadata for later analysis.
    event["scenario_context"] = profile_name

    return event, scenario_profiles


def normalise_priority(
        priority: str | None,
) -> str:
    if not priority:
        return "UNKNOWN"

    for label in (
            "P1",
            "P2",
            "P3",
            "P4",
    ):
        if priority.startswith(label):
            return label

    return "UNKNOWN"


def main() -> None:

    random.seed(RANDOM_SEED)

    base_events = load_json(INPUT_FILE)

    if not isinstance(base_events, list):
        raise ValueError(
            "Input event data must contain a JSON list."
        )

    generated_events = []

    for scenario_number in range(
            NUMBER_OF_SCENARIOS
    ):

        base_event = random.choice(
            base_events
        )

        event, scenario_profiles = (
            create_scenario(
                base_event,
                scenario_number,
            )
        )

        # Rules intentionally disabled for this controlled experiment.
        #
        # The asset context is explicitly provided through a static
        # profile so that the experiment can vary deployment context
        # independently while still using the existing enrichment,
        # STRIDE, scoring and recommendation framework.
        enriched = enrich_event(
            event=event,
            context_profiles=scenario_profiles,
            context_rules={"rules": []},
        )

        generated_events.append(
            enriched
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
            "w",
            encoding="utf-8",
    ) as file:

        json.dump(
            generated_events,
            file,
            indent=2,
        )

    print(
        "V2 context-diverse scenario generation completed."
    )

    print(
        f"Base events: {len(base_events)}"
    )

    print(
        f"Generated scenarios: "
        f"{len(generated_events)}"
    )

    print(
        f"Saved to: {OUTPUT_FILE}"
    )

    # -------------------------------------------------------------
    # Priority distribution
    # -------------------------------------------------------------

    priority_distribution = {}

    for event in generated_events:

        priority = normalise_priority(
            event.get("priority_level")
        )

        priority_distribution[priority] = (
                priority_distribution.get(
                    priority,
                    0,
                )
                + 1
        )

    print("\nPriority distribution:")

    for priority in sorted(
            priority_distribution
    ):
        print(
            f"  {priority}: "
            f"{priority_distribution[priority]}"
        )

    # -------------------------------------------------------------
    # Context distribution
    # -------------------------------------------------------------

    context_distribution = {}

    for event in generated_events:

        profile = event.get(
            "scenario_context",
            "unknown",
        )

        context_distribution[profile] = (
                context_distribution.get(
                    profile,
                    0,
                )
                + 1
        )

    print("\nScenario context distribution:")

    for profile in sorted(
            context_distribution
    ):
        print(
            f"  {profile}: "
            f"{context_distribution[profile]}"
        )


if __name__ == "__main__":
    main()