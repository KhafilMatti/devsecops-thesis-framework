import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

INPUT_FILE = Path("data/enriched_events.json")
OUTPUT_FILE = Path("data/explainability_metrics.json")


def load_events(path: Path) -> list[dict[str, Any]]:
    """Load the enriched event dataset."""
    if not path.exists():
        raise FileNotFoundError(
            f"Enriched events file not found: {path}. "
            "Run riskenrichment.py first."
        )

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(
            f"{path} must contain a JSON list of events."
        )

    return data


def percentage(count: int, total: int) -> float:
    """Return a percentage rounded to two decimal places."""
    if total == 0:
        return 0.0

    return round((count / total) * 100, 2)


def contains_context_reason(reasons: list[str]) -> bool:
    """Check whether an explanation refers to asset or deployment context."""
    context_terms = (
        "internet-facing",
        "runtime",
        "production",
        "business criticality",
        "data sensitivity",
        "deployment",
        "asset",
    )

    combined_text = " ".join(reasons).lower()

    return any(term in combined_text for term in context_terms)


def contains_stride_reason(
        reasons: list[str],
        stride_categories: list[str],
) -> bool:
    """Check whether the explanation discusses at least one STRIDE category."""
    if not stride_categories:
        return False

    combined_text = " ".join(reasons).lower()

    return any(
        category.lower() in combined_text
        for category in stride_categories
        if category != "Unclassified"
    )


def contains_actionability_reason(
        event: dict[str, Any],
        reasons: list[str],
) -> bool:
    """Check whether remediation or an actionable next step is explained."""
    combined_text = " ".join(reasons).lower()

    action_terms = (
        "patched version",
        "remediation",
        "upgrade",
        "add ",
        "combine ",
        "remove ",
        "fix",
        "actionable",
    )

    has_action_text = any(
        term in combined_text
        for term in action_terms
    )

    has_source_remediation = bool(
        event.get("patched_version")
        or event.get("resolution")
    )

    return has_action_text and has_source_remediation


def has_valid_score_breakdown(
        event: dict[str, Any],
        score_components: dict[str, Any],
) -> bool:
    """
    Check whether the explanation exposes the main scoring components and
    whether the uncapped sum is consistent with the stored risk score.
    """
    required_components = {
        "severity",
        "cvss",
        "stride",
        "context",
        "remediation_actionability",
        "devsecops_relevance",
    }

    if not required_components.issubset(score_components):
        return False

    component_values = [
        score_components.get(name)
        for name in required_components
    ]

    if not all(
            isinstance(value, (int, float))
            for value in component_values
    ):
        return False

    uncapped_total = sum(component_values)
    expected_score = min(int(uncapped_total), 100)
    actual_score = event.get("risk_score")

    return (
            isinstance(actual_score, (int, float))
            and int(actual_score) == expected_score
    )


def explanation_signature(event: dict[str, Any]) -> tuple[Any, ...]:
    """
    Build a structural signature for consistency analysis.

    Events with the same signature should normally produce explanations
    using the same major types of reasoning.
    """
    context = event.get("asset_context") or {}

    return (
        event.get("event_type"),
        str(event.get("severity") or "").lower(),
        bool(event.get("cvss_score")),
        bool(event.get("patched_version") or event.get("resolution")),
        bool(context.get("internet_facing")),
        bool(context.get("runtime_reachable")),
        str(context.get("environment") or "").lower(),
        str(context.get("business_criticality") or "").lower(),
        tuple(sorted(event.get("stride_categories") or [])),
    )


def explanation_feature_set(
        event: dict[str, Any],
        reasons: list[str],
) -> frozenset[str]:
    """Convert an explanation into a comparable set of feature labels."""
    features: set[str] = set()
    text = " ".join(reasons).lower()

    if event.get("severity"):
        features.add("severity")

    if event.get("cvss_score"):
        features.add("cvss")

    if "internet-facing" in text:
        features.add("internet_facing")

    if "runtime" in text:
        features.add("runtime_reachable")

    if "production" in text:
        features.add("production_environment")

    if "business criticality" in text:
        features.add("business_criticality")

    if any(
            category.lower() in text
            for category in event.get("stride_categories") or []
            if category != "Unclassified"
    ):
        features.add("stride")

    if event.get("patched_version") or event.get("resolution"):
        if any(
                term in text
                for term in (
                        "patched version",
                        "remediation",
                        "actionable",
                        "upgrade",
                        "add ",
                        "combine ",
                        "remove ",
                )
        ):
            features.add("actionability")

    if event.get("event_type") == "dependency_vulnerability":
        if "software dependency" in text:
            features.add("event_type")

    if event.get("event_type") == "misconfiguration":
        if "configuration" in text:
            features.add("event_type")

    return frozenset(features)


def evaluate_consistency(
        events: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Compare explanations for events with equivalent input characteristics.

    A group is consistent when every event in that group contains the same
    explanation feature set.
    """
    groups: dict[
        tuple[Any, ...],
        list[frozenset[str]],
    ] = defaultdict(list)

    for event in events:
        explanation = event.get("explanation") or {}
        reasons = explanation.get("reasons") or []

        groups[explanation_signature(event)].append(
            explanation_feature_set(event, reasons)
        )

    comparable_groups = {
        signature: feature_sets
        for signature, feature_sets in groups.items()
        if len(feature_sets) > 1
    }

    consistent_groups = sum(
        len(set(feature_sets)) == 1
        for feature_sets in comparable_groups.values()
    )

    total_groups = len(comparable_groups)

    return {
        "comparable_groups": total_groups,
        "consistent_groups": consistent_groups,
        "consistency_percentage": percentage(
            consistent_groups,
            total_groups,
        ),
    }


def evaluate_event(event: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one event against the explainability criteria."""
    explanation = event.get("explanation") or {}
    summary = explanation.get("summary")
    reasons = explanation.get("reasons") or []
    score_components = explanation.get("score_components") or {}
    context_profile = explanation.get("context_profile")

    completeness = bool(
        isinstance(summary, str)
        and summary.strip()
        and isinstance(reasons, list)
        and len(reasons) > 0
    )

    transparency = has_valid_score_breakdown(
        event,
        score_components,
    )

    context_awareness = contains_context_reason(reasons)

    actionability = contains_actionability_reason(
        event,
        reasons,
    )

    stride_explanation = contains_stride_reason(
        reasons,
        event.get("stride_categories") or [],
        )

    context_profile_present = bool(context_profile)

    passed_criteria = sum(
        (
            completeness,
            transparency,
            context_awareness,
            actionability,
            stride_explanation,
            context_profile_present,
        )
    )

    return {
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type"),
        "priority_level": event.get("priority_level"),
        "risk_score": event.get("risk_score"),
        "completeness": completeness,
        "transparency": transparency,
        "context_awareness": context_awareness,
        "actionability": actionability,
        "stride_explanation": stride_explanation,
        "context_profile_present": context_profile_present,
        "reason_count": len(reasons),
        "criteria_passed": passed_criteria,
        "criteria_total": 6,
        "explainability_score": round(
            (passed_criteria / 6) * 100,
            2,
            ),
    }


def main() -> None:
    events = load_events(INPUT_FILE)

    event_results = [
        evaluate_event(event)
        for event in events
    ]



    total_events = len(event_results)

    print("\nEvents that failed the STRIDE explanation criterion:")

    for result in event_results:
        if not result["stride_explanation"]:
            print(
                f"- {result['event_id']} "
                f"({result['event_type']})"
            )

    criterion_names = (
        "completeness",
        "transparency",
        "context_awareness",
        "actionability",
        "stride_explanation",
        "context_profile_present",
    )

    criterion_counts = {
        criterion: sum(
            result[criterion]
            for result in event_results
        )
        for criterion in criterion_names
    }

    criterion_percentages = {
        criterion: percentage(
            count,
            total_events,
        )
        for criterion, count in criterion_counts.items()
    }

    average_reason_count = round(
        (
                sum(result["reason_count"] for result in event_results)
                / total_events
        )
        if total_events
        else 0.0,
        2,
    )

    average_explainability_score = round(
        (
                sum(
                    result["explainability_score"]
                    for result in event_results
                )
                / total_events
        )
        if total_events
        else 0.0,
        2,
    )

    event_type_counts = Counter(
        result["event_type"]
        for result in event_results
    )

    priority_counts = Counter(
        result["priority_level"]
        for result in event_results
    )

    consistency = evaluate_consistency(events)

    metrics = {
        "experiment": "Experiment 3 - Explainability Evaluation",
        "input_file": str(INPUT_FILE),
        "events_analysed": total_events,
        "criteria": {
            "completeness": (
                "An explanation contains a non-empty summary and at "
                "least one human-readable reason."
            ),
            "transparency": (
                "The principal score components are disclosed and "
                "reproduce the stored risk score."
            ),
            "context_awareness": (
                "The explanation refers to asset, runtime, production "
                "or business context."
            ),
            "actionability": (
                "The explanation communicates available patch or "
                "configuration remediation information."
            ),
            "stride_explanation": (
                "At least one classified STRIDE impact is explained "
                "where applicable."
            ),
            "context_profile_present": (
                "The contextual profile used for the event is disclosed."
            ),
        },
        "criterion_counts": criterion_counts,
        "criterion_percentages": criterion_percentages,
        "average_reason_count": average_reason_count,
        "average_explainability_score": (
            average_explainability_score
        ),
        "consistency": consistency,
        "events_by_type": dict(event_type_counts),
        "events_by_priority": dict(priority_counts),
        "event_results": event_results,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4)

    print("Experiment 3 - Explainability Evaluation")
    print("=" * 55)
    print(f"Events analysed: {total_events}")
    print(
        f"Average explanation reasons: "
        f"{average_reason_count}"
    )
    print(
        f"Average explainability score: "
        f"{average_explainability_score}%"
    )

    print("\nCriterion results:")

    for criterion in criterion_names:
        print(
            f"- {criterion}: "
            f"{criterion_counts[criterion]}/{total_events} "
            f"({criterion_percentages[criterion]}%)"
        )

    print("\nConsistency results:")
    print(
        "- Comparable groups:",
        consistency["comparable_groups"],
    )
    print(
        "- Consistent groups:",
        consistency["consistent_groups"],
    )
    print(
        "- Consistency percentage:",
        f"{consistency['consistency_percentage']}%",
    )

    print(f"\nSaved output to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()