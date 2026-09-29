from pathlib import Path
import json
import sys


# =========================================================
# 1. PROJECT PATHS
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

ANALYSIS_DIR = PROJECT_ROOT / "src" / "analysis"

if str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))


# =========================================================
# 2. IMPORT EXISTING FRAMEWORK
# =========================================================

from riskenrichment import enrich_event


# =========================================================
# 3. FILE PATHS
# =========================================================

INPUT_FILE = (
        PROJECT_ROOT
        / "external_validation"
        / "processed"
        / "external_validation_events.json"
)


RESULTS_DIR = (
        PROJECT_ROOT
        / "external_validation"
        / "results"
)

OUTPUT_FILE = (
        RESULTS_DIR
        / "external_validation_framework_results.json"
)


# =========================================================
# 4. CONTROLLED CONTEXT
# =========================================================
#
# Every external CVE receives the same organisational
# context.
#
# This is deliberate. Public CVE data does not contain
# organisation-specific business context, so changing
# context between CVEs would introduce an uncontrolled
# variable into the experiment.
#

CONTROLLED_CONTEXT = {
    "default": {
        "environment": "production",
        "internet_facing": False,
        "runtime_reachable": True,
        "business_criticality": "medium",
        "data_sensitivity": "medium",
    }
}


# No context rules are used in this experiment.
#
# This ensures every CVE receives exactly the same
# controlled context.
#

CONTROLLED_RULES = {
    "rules": []
}


# =========================================================
# 5. LOAD INPUT
# =========================================================

print("=" * 70)
print("EXTERNAL VALIDATION - FRAMEWORK RUN")
print("=" * 70)

if not INPUT_FILE.exists():
    raise FileNotFoundError(
        f"Input file not found: {INPUT_FILE}"
    )


with INPUT_FILE.open(
        "r",
        encoding="utf-8",
) as file:

    events = json.load(file)

print(f"\nReading input from: {INPUT_FILE}")
print(f"Loaded JSON type: {type(events).__name__}")
print(f"Number of loaded events: {len(events)}")


if not isinstance(events, list):
    raise ValueError(
        "External validation input must contain a JSON list."
    )


if len(events) != 100:
    raise ValueError(
        f"Expected 100 external events, found {len(events)}."
    )


print(f"\nLoaded external events: {len(events)}")


# =========================================================
# 6. RUN EXISTING FRAMEWORK
# =========================================================

results = []


for number, event in enumerate(events, start=1):

    enriched = enrich_event(
        event=event,
        context_profiles=CONTROLLED_CONTEXT,
        context_rules=CONTROLLED_RULES,
    )

    results.append(enriched)

    print(
        f"[{number:03d}/100] "
        f"{event.get('external_validation', {}).get('cve_id')} "
        f"-> {enriched.get('priority_level')} "
        f"(risk={enriched.get('risk_score')}, "
        f"adjusted={enriched.get('exploitability_adjusted_score')})"
    )


# =========================================================
# 7. VALIDATION CHECKS
# =========================================================

if len(results) != 100:
    raise ValueError(
        f"Expected 100 framework results, got {len(results)}."
    )


unique_ids = {
    event.get("event_id")
    for event in results
}

if len(unique_ids) != 100:
    raise ValueError(
        "Duplicate or missing event IDs detected."
    )


# =========================================================
# 8. SORT OUTPUT
# =========================================================

results.sort(
    key=lambda event: event.get(
        "exploitability_adjusted_score",
        0,
    ),
    reverse=True,
)


# =========================================================
# 9. SAVE RESULTS
# =========================================================

RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
) as file:

    json.dump(
        results,
        file,
        indent=2,
    )


# =========================================================
# 10. SUMMARISE PRIORITIES
# =========================================================

base_priority_counts = {}
adjusted_priority_counts = {}


for event in results:

    base_priority = event.get(
        "priority_level",
        "Unknown",
    )

    adjusted_priority = event.get(
        "exploitability_adjusted_priority",
        "Unknown",
    )

    base_priority_counts[base_priority] = (
            base_priority_counts.get(base_priority, 0) + 1
    )

    adjusted_priority_counts[adjusted_priority] = (
            adjusted_priority_counts.get(adjusted_priority, 0) + 1
    )


print("\n" + "=" * 70)
print("BASE PRIORITY DISTRIBUTION")
print("=" * 70)

for priority, count in sorted(
        base_priority_counts.items()
):
    print(f"{priority}: {count}")


print("\n" + "=" * 70)
print("EXPLOITABILITY-ADJUSTED PRIORITY DISTRIBUTION")
print("=" * 70)

for priority, count in sorted(
        adjusted_priority_counts.items()
):
    print(f"{priority}: {count}")


# =========================================================
# 11. KEV SANITY CHECK
# =========================================================

kev_count = sum(
    1
    for event in results
    if event
    .get("external_validation", {})
    .get("cisa_kev") is True
)

non_kev_count = len(results) - kev_count


print("\nExternal labels preserved:")
print(f"CISA KEV: {kev_count}")
print(f"Non-KEV:  {non_kev_count}")


# =========================================================
# 12. FINISH
# =========================================================

print("\n" + "=" * 70)
print("FRAMEWORK EXTERNAL VALIDATION COMPLETE")
print("=" * 70)

print(f"\nSaved results to:\n{OUTPUT_FILE}")