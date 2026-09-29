import json
from pathlib import Path
from typing import Any
from contextresolver import resolve_asset_context
from recommendationengine import generate_recommendation
from exploitabilityengine import (
    assign_adjusted_priority,
    calculate_adjusted_score,
    calculate_exploitability,
)

INPUT_FILE = Path("data/all_normalised_events.json")
CONTEXT_FILE = Path("data/asset_context.json")
OUTPUT_FILE = Path("data/enriched_events.json")
CONTEXT_RULES_FILE = Path("data/asset_context_rules.json")


SEVERITY_SCORES = {
    "critical": 30,
    "high": 24,
    "moderate": 16,
    "medium": 16,
    "low": 8,
    "unknown": 0,
    None: 0,
}

BUSINESS_CRITICALITY_SCORES = {
    "high": 10,
    "medium": 6,
    "low": 2,
}

DATA_SENSITIVITY_SCORES = {
    "high": 6,
    "medium": 3,
    "low": 1,
}


def load_json(path: Path) -> Any:
    """Load JSON data from a required file."""
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_asset_path(event: dict[str, Any]) -> str | None:
    """
    Return the path used to associate an event with its contextual profile.

    Dependency events normally use manifest_path, while configuration
    events use resource_path.
    """
    return (
            event.get("resource_path")
            or event.get("manifest_path")
    )


def apply_context(
        event: dict[str, Any],
        context_profiles: dict[str, Any],
) -> dict[str, Any]:
    """Apply a predefined asset-context profile to an event."""
    asset_path = get_asset_path(event)

    default_context = context_profiles.get("default", {})
    asset_context = context_profiles.get(asset_path, {})

    context = {
        **default_context,
        **asset_context,
    }

    context["asset_path"] = asset_path
    context["context_profile"] = (
        asset_path if asset_path in context_profiles else "default"
    )

    return context


def map_stride(event: dict[str, Any]) -> list[str]:
    """Map vulnerability and misconfiguration text to STRIDE categories."""
    title = str(event.get("title") or "").lower()
    description = str(event.get("description") or "").lower()
    message = str(event.get("message") or "").lower()
    resolution = str(event.get("resolution") or "").lower()

    text = " ".join(
        [title, description, message, resolution]
    )

    stride: set[str] = set()

    if any(
            phrase in text
            for phrase in (
                    "remote code",
                    "code execution",
                    "injection",
                    "uncontrolled behavior",
                    "uncontrolled update",
            )
    ):
        stride.add("Tampering")

    if any(
            phrase in text
            for phrase in (
                    "remote code",
                    "code execution",
                    "root user",
                    "container escape",
                    "privilege",
            )
    ):
        stride.add("Elevation of Privilege")

    if any(
            phrase in text
            for phrase in (
                    "information disclosure",
                    "information leak",
                    "sensitive information",
                    "exposure",
            )
    ):
        stride.add("Information Disclosure")

    if any(
            phrase in text
            for phrase in (
                    "denial of service",
                    "dos",
                    "availability",
                    "healthcheck",
                    "health check",
            )
    ):
        stride.add("Denial of Service")

    if any(
            phrase in text
            for phrase in (
                    "authentication bypass",
                    "valid account",
                    "identity",
                    "credential",
            )
    ):
        stride.add("Spoofing")

    if any(
            phrase in text
            for phrase in (
                    "logging",
                    "audit",
                    "accountability",
                    "traceability",
            )
    ):
        stride.add("Repudiation")

    if not stride:
        stride.add("Unclassified")

    return sorted(stride)


def calculate_cvss_points(cvss_score: float) -> int:
    """Translate CVSS into a bounded scoring contribution."""
    if cvss_score >= 9:
        return 18
    if cvss_score >= 7:
        return 14
    if cvss_score >= 4:
        return 8
    if cvss_score > 0:
        return 4

    return 0


def calculate_stride_points(
        stride_categories: list[str],
) -> int:
    """Score the potential impact represented by STRIDE categories."""
    stride_weights = {
        "Elevation of Privilege": 5,
        "Tampering": 4,
        "Information Disclosure": 4,
        "Denial of Service": 3,
        "Spoofing": 3,
        "Repudiation": 2,
        "Unclassified": 0,
    }

    return min(
        12,
        sum(
            stride_weights.get(category, 0)
            for category in set(stride_categories)
        ),
    )


def calculate_context_points(
        context: dict[str, Any],
) -> tuple[int, dict[str, int]]:
    """Calculate the contextual contribution and retain its components."""
    components = {
        "internet_facing": (
            8 if context.get("internet_facing") else 0
        ),
        "runtime_reachable": (
            7 if context.get("runtime_reachable") else 0
        ),
        "production_environment": (
            6
            if str(context.get("environment")).lower() == "production"
            else 0
        ),
        "business_criticality": BUSINESS_CRITICALITY_SCORES.get(
            str(context.get("business_criticality", "low")).lower(),
            0,
        ),
        "data_sensitivity": DATA_SENSITIVITY_SCORES.get(
            str(context.get("data_sensitivity", "low")).lower(),
            0,
        ),
    }

    return sum(components.values()), components


def calculate_priority_score(
        event: dict[str, Any],
        stride_categories: list[str],
        context: dict[str, Any],
) -> tuple[int, dict[str, int]]:
    """Calculate a transparent context-aware risk score."""
    severity = str(event.get("severity") or "unknown").lower()
    cvss_score = float(event.get("cvss_score") or 0)

    severity_points = SEVERITY_SCORES.get(severity, 0)
    cvss_points = calculate_cvss_points(cvss_score)
    stride_points = calculate_stride_points(stride_categories)

    context_points, context_components = calculate_context_points(
        context
    )

    remediation_points = 0

    if event.get("patched_version"):
        remediation_points = 4
    elif (
            event.get("event_type") == "misconfiguration"
            and event.get("resolution")
    ):
        remediation_points = 4

    event_type_points = 0

    if event.get("event_type") in {
        "dependency_vulnerability",
        "misconfiguration",
    }:
        event_type_points = 2

    score_components = {
        "severity": severity_points,
        "cvss": cvss_points,
        "stride": stride_points,
        "context": context_points,
        "remediation_actionability": remediation_points,
        "devsecops_relevance": event_type_points,
        **{
            f"context_{name}": value
            for name, value in context_components.items()
        },
    }

    total_score = (
            severity_points
            + cvss_points
            + stride_points
            + context_points
            + remediation_points
            + event_type_points
    )

    return min(total_score, 100), score_components


def assign_priority_level(score: int) -> str:
    """Convert the numerical score into an operational priority."""
    if score >= 80:
        return "P1 - Immediate"
    if score >= 65:
        return "P2 - High"
    if score >= 45:
        return "P3 - Medium"

    return "P4 - Low"


def generate_explanation(
        event: dict[str, Any],
        score: int,
        priority: str,
        stride_categories: list[str],
        context: dict[str, Any],
        score_components: dict[str, int],
) -> dict[str, Any]:
    """Generate a human-readable and machine-readable explanation."""
    reasons: list[str] = []

    severity = event.get("severity")
    cvss = float(event.get("cvss_score") or 0)

    if severity:
        reasons.append(
            f"The scanner assigned a {severity} severity rating."
        )

    if cvss > 0:
        reasons.append(
            f"The vulnerability has a CVSS score of {cvss}."
        )
    elif event.get("event_type") == "misconfiguration":
        reasons.append(
            "This is a configuration finding and therefore does not "
            "have a CVSS score; it is evaluated using severity, "
            "security impact and deployment context."
        )

    if context.get("internet_facing"):
        reasons.append(
            "The affected asset is internet-facing, increasing its "
            "potential exposure to external attackers."
        )

    if context.get("runtime_reachable"):
        reasons.append(
            "The affected component or configuration is considered "
            "reachable during runtime."
        )

    if str(context.get("environment")).lower() == "production":
        reasons.append(
            "The event affects a production-context asset."
        )

    criticality = context.get("business_criticality")

    if criticality:
        reasons.append(
            f"The affected asset has {criticality} business criticality."
        )

    if "Elevation of Privilege" in stride_categories:
        reasons.append(
            "The event maps to Elevation of Privilege because successful "
            "exploitation or misuse could increase attacker control."
        )

    if "Tampering" in stride_categories:
        reasons.append(
            "The event maps to Tampering because it could permit or "
            "contribute to unauthorised modification."
        )

    if "Information Disclosure" in stride_categories:
        reasons.append(
            "The event maps to Information Disclosure because sensitive "
            "information could be exposed."
        )

    if "Denial of Service" in stride_categories:
        reasons.append(
            "The event maps to Denial of Service because it could affect "
            "system or application availability."
        )

    if "Repudiation" in stride_categories:
        reasons.append(
            "The event maps to Repudiation because weaknesses in logging, "
            "auditability or traceability may make malicious activity "
            "more difficult to attribute."
        )

    if event.get("event_type") == "dependency_vulnerability":
        reasons.append(
            "The finding affects a software dependency used in the "
            "CI/CD software supply chain."
        )

    if event.get("event_type") == "misconfiguration":
        reasons.append(
            "The finding represents an insecure build or deployment "
            "configuration within the CI/CD pipeline."
        )

    if event.get("patched_version"):
        reasons.append(
            f"A patched version is available "
            f"({event['patched_version']}), making remediation actionable."
        )

    if (
            event.get("event_type") == "misconfiguration"
            and event.get("resolution")
    ):
        reasons.append(
            f"Trivy provides an actionable remediation: "
            f"{event['resolution']}."
        )

    return {
        "summary": (
            f"This event was assigned {priority} with a "
            f"context-aware risk score of {score}/100."
        ),
        "reasons": reasons,
        "score_components": score_components,
        "context_profile": context.get("context_profile"),
    }


def enrich_event(
        event: dict[str, Any],
        context_profiles: dict[str, Any],
        context_rules: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply context, STRIDE mapping, scoring, explanation and recommendations."""
    context_rules = context_rules or {"rules": []}

    context = resolve_asset_context(
        event=event,
        static_profiles=context_profiles,
        rule_configuration=context_rules,
    )

    stride_categories = map_stride(event)

    score, score_components = calculate_priority_score(
        event=event,
        stride_categories=stride_categories,
        context=context,
    )

    priority = assign_priority_level(score)

    explanation = generate_explanation(
        event=event,
        score=score,
        priority=priority,
        stride_categories=stride_categories,
        context=context,
        score_components=score_components,
    )

    exploitability_input = event.copy()
    exploitability_input["asset_context"] = context
    exploitability_input["stride_categories"] = stride_categories

    exploitability = calculate_exploitability(
        exploitability_input
    )

    exploitability_adjusted_score = calculate_adjusted_score(
        base_risk_score=score,
        exploitability_score=exploitability["score"],
    )

    exploitability_adjusted_priority = (
        assign_adjusted_priority(
            exploitability_adjusted_score
        )
    )

    recommendation_input = event.copy()
    recommendation_input["asset_context"] = context
    recommendation_input["stride_categories"] = stride_categories
    recommendation_input["risk_score"] = score
    recommendation_input["priority_level"] = priority

    recommendation = generate_recommendation(
        recommendation_input
    )


    enriched_event = event.copy()
    enriched_event["asset_context"] = context
    enriched_event["stride_categories"] = stride_categories
    enriched_event["risk_score"] = score
    enriched_event["priority_level"] = priority
    enriched_event["explanation"] = explanation
    enriched_event["recommendation"] = recommendation
    enriched_event["exploitability"] = exploitability
    enriched_event["exploitability_adjusted_score"] = (
        exploitability_adjusted_score
    )
    enriched_event["exploitability_adjusted_priority"] = (
        exploitability_adjusted_priority
    )

    return enriched_event

def main() -> None:
    events = load_json(INPUT_FILE)
    context_profiles = load_json(CONTEXT_FILE)
    context_rules = load_json(CONTEXT_RULES_FILE)

    if not isinstance(events, list):
        raise ValueError(
            f"{INPUT_FILE} must contain a JSON list of events."
        )

    if not isinstance(context_profiles, dict):
        raise ValueError(
            f"{CONTEXT_FILE} must contain a JSON object."
        )
    if not isinstance(context_rules, dict):
        raise ValueError(
            f"{CONTEXT_RULES_FILE} must contain a JSON object."
        )
    enriched_events = [
        enrich_event(
            event=event,
            context_profiles=context_profiles,
            context_rules=context_rules,
        )
        for event in events
    ]


    enriched_events.sort(
        key=lambda event: event["risk_score"],
        reverse=True,
    )

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(enriched_events, file, indent=4)

    vulnerability_count = sum(
        event.get("event_type") == "dependency_vulnerability"
        for event in enriched_events
    )

    misconfiguration_count = sum(
        event.get("event_type") == "misconfiguration"
        for event in enriched_events
    )

    print(f"Enriched {len(enriched_events)} events")
    print(f"Dependency vulnerabilities: {vulnerability_count}")
    print(f"Misconfigurations: {misconfiguration_count}")
    print(f"Saved output to {OUTPUT_FILE}")
    print(f"Saved output to {OUTPUT_FILE}")

    assignment_methods: dict[str, int] = {}

    for event in enriched_events:
        method = (
            event.get("asset_context", {})
            .get("context_assignment_method", "unknown")
        )

        assignment_methods[method] = (
                assignment_methods.get(method, 0) + 1
        )

    print("\nContext assignment methods:")

    for method, count in sorted(assignment_methods.items()):
        print(f"- {method}: {count}")

    for event in enriched_events:
        print("-" * 70)
        print("Event ID:", event.get("event_id"))
        print("Event type:", event.get("event_type"))
        print("Title:", event.get("title"))
        print("Severity:", event.get("severity"))
        print("CVE:", event.get("cve_id"))
        print(
            "Misconfiguration ID:",
            event.get("misconfiguration_id"),
        )
        print("CVSS:", event.get("cvss_score"))
        print(
            "STRIDE:",
            ", ".join(event.get("stride_categories", [])),
        )
        print("Risk Score:", event.get("risk_score"))
        print("Priority:", event.get("priority_level"))

        asset_context = event.get("asset_context", {})

        print(
            "Context profile:",
            asset_context.get("context_profile"),
        )
        print(
            "Assignment method:",
            asset_context.get("context_assignment_method"),
        )
        print(
            "Context rule:",
            asset_context.get("context_rule_id"),
        )
        print(
            "Assignment confidence:",
            asset_context.get(
                "context_assignment_confidence"
            ),
        )
        print(
            "Match evidence:",
            ", ".join(
                asset_context.get(
                    "context_match_evidence",
                    [],
                )
            ),
        )


        recommendation = event.get("recommendation", {})

        print(
            "Recommended action:",
            recommendation.get("recommended_action"),
        )
        print(
            "Recommendation status:",
            recommendation.get("recommendation_status"),
        )
        print(
            "Remediation type:",
            recommendation.get("remediation_type"),
        )
        print(
            "Estimated effort:",
            recommendation.get("estimated_effort"),
        )
        print(
            "Operational disruption:",
            recommendation.get(
                "estimated_operational_disruption"
            ),
        )
        print(
            "Patch available:",
            recommendation.get("patch_available"),
        )
        print(
            "Explanation:",
            event.get("explanation", {}).get("summary"),
        )
        exploitability = event.get("exploitability", {})

        print(
            "Exploitability score:",
            f"{exploitability.get('score')}/10",
        )
        print(
            "Exploitability level:",
            exploitability.get("level"),
        )
        print(
            "Exploitability-adjusted score:",
            event.get("exploitability_adjusted_score"),
        )
        print(
            "Exploitability-adjusted priority:",
            event.get(
                "exploitability_adjusted_priority"
            ),
        )
        print(
            "Exploitability factors:",
            ", ".join(
                factor.get("factor", "")
                for factor in exploitability.get(
                    "factors",
                    [],
                )
            ),
        )


if __name__ == "__main__":
    main()