from typing import Any


EFFORT_LEVELS = {
    "very_low": {
        "label": "Very Low",
        "score": 1,
    },
    "low": {
        "label": "Low",
        "score": 2,
    },
    "medium": {
        "label": "Medium",
        "score": 3,
    },
    "high": {
        "label": "High",
        "score": 4,
    },
}


def determine_remediation_type(
        event: dict[str, Any],
) -> str:

    if event.get("event_type") == "dependency_vulnerability":
        if event.get("patched_version"):
            return "dependency_upgrade"

        return "dependency_investigation"

    if event.get("event_type") == "misconfiguration":
        return "configuration_change"

    return "manual_security_review"


def estimate_effort(
        event: dict[str, Any],
        remediation_type: str,
) -> dict[str, Any]:

    if remediation_type == "configuration_change":
        title = str(event.get("title") or "").lower()

        very_low_effort_terms = (
            "healthcheck",
            "latest",
            "user should not be",
            "package-manager",
        )

        if any(term in title for term in very_low_effort_terms):
            return EFFORT_LEVELS["very_low"]

        return EFFORT_LEVELS["low"]

    if remediation_type == "dependency_upgrade":
        installed_version = str(
            event.get("installed_version") or ""
        )

        patched_version = str(
            event.get("patched_version") or ""
        )

        if not installed_version:
            return EFFORT_LEVELS["medium"]

        installed_major = installed_version.split(".")[0]
        patched_major = patched_version.split(".")[0]

        if installed_major and installed_major == patched_major:
            return EFFORT_LEVELS["low"]

        return EFFORT_LEVELS["medium"]

    if remediation_type == "dependency_investigation":
        return EFFORT_LEVELS["high"]

    return EFFORT_LEVELS["medium"]


def estimate_operational_disruption(
        event: dict[str, Any],
        effort: dict[str, Any],
) -> str:

    context = event.get("asset_context") or {}

    environment = str(
        context.get("environment") or ""
    ).lower()

    runtime_reachable = bool(
        context.get("runtime_reachable")
    )

    if (
            environment == "production"
            and runtime_reachable
            and effort["score"] >= 3
    ):
        return "Medium"

    if environment == "production":
        return "Low"

    return "Very Low"


def generate_recommended_action(
        event: dict[str, Any],
        remediation_type: str,
) -> str:
    """Generates the primary remediation recommendation."""
    if remediation_type == "dependency_upgrade":
        patched_version = event.get("patched_version")

        return (
            f"Upgrade {event.get('package_name') or 'the affected dependency'} "
            f"to a secure version: {patched_version}."
        )

    if remediation_type == "dependency_investigation":
        return (
            "Investigate the affected dependency, confirm exploitability "
            "and identify an appropriate patched or replacement version."
        )

    if remediation_type == "configuration_change":
        resolution = event.get("resolution")

        if resolution:
            return str(resolution)

        return (
            "Update the insecure configuration according to the scanner's "
            "recommended secure configuration."
        )

    return (
        "Perform a manual security review and define an appropriate "
        "remediation plan."
    )


def generate_validation_steps(
        event: dict[str, Any],
        remediation_type: str,
) -> list[str]:
    """Provides practical post-remediation validation steps."""
    if remediation_type == "dependency_upgrade":
        return [
            "Update the dependency declaration or lock file.",
            "Run the project's automated unit and integration tests.",
            "Re-run Dependabot and Trivy scanning.",
            "Confirm that the original finding no longer appears.",
            "Monitor the application after deployment for regressions.",
        ]

    if remediation_type == "configuration_change":
        return [
            "Apply the recommended configuration change.",
            "Rebuild the container or application artefact.",
            "Run the relevant automated tests.",
            "Re-run Trivy misconfiguration scanning.",
            "Confirm that the configuration finding is resolved.",
        ]

    return [
        "Confirm the affected component and exposure conditions.",
        "Review vendor or maintainer guidance.",
        "Test the proposed remediation in a non-production environment.",
        "Re-run the relevant security scanner.",
    ]


def generate_recommendation_reason(
        event: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []

    priority = event.get("priority_level")
    risk_score = event.get("risk_score")
    context = event.get("asset_context") or {}

    if priority:
        reasons.append(
            f"The finding is currently classified as {priority}."
        )

    if isinstance(risk_score, (int, float)):
        reasons.append(
            f"The context-aware risk score is {risk_score}/100."
        )

    if context.get("internet_facing"):
        reasons.append(
            "The affected asset is internet-facing."
        )

    if context.get("runtime_reachable"):
        reasons.append(
            "The affected component is reachable during runtime."
        )

    if (
            str(context.get("environment") or "").lower()
            == "production"
    ):
        reasons.append(
            "The finding affects a production-context asset."
        )

    if event.get("patched_version"):
        reasons.append(
            "A patched version is available, making remediation actionable."
        )

    if event.get("resolution"):
        reasons.append(
            "The scanner provides a specific configuration remediation."
        )

    return reasons


def assign_recommendation_status(
        event: dict[str, Any],
) -> str:
    """Convert the priority level into an operational recommendation."""
    priority = str(
        event.get("priority_level") or ""
    ).lower()

    if "p1" in priority:
        return "Remediate immediately"

    if "p2" in priority:
        return "Schedule in the next remediation window"

    if "p3" in priority:
        return "Plan and remediate after higher-priority findings"

    return "Monitor and address during routine maintenance"


def generate_recommendation(
        event: dict[str, Any],
) -> dict[str, Any]:
    """Generates a complete explainable remediation recommendation."""
    remediation_type = determine_remediation_type(event)

    effort = estimate_effort(
        event=event,
        remediation_type=remediation_type,
    )

    disruption = estimate_operational_disruption(
        event=event,
        effort=effort,
    )

    return {
        "recommended_action": generate_recommended_action(
            event=event,
            remediation_type=remediation_type,
        ),
        "recommendation_status": assign_recommendation_status(
            event
        ),
        "remediation_type": remediation_type,
        "estimated_effort": effort["label"],
        "estimated_effort_score": effort["score"],
        "estimated_operational_disruption": disruption,
        "patch_available": bool(
            event.get("patched_version")
        ),
        "scanner_resolution_available": bool(
            event.get("resolution")
        ),
        "recommendation_reasons": (
            generate_recommendation_reason(event)
        ),
        "validation_steps": generate_validation_steps(
            event=event,
            remediation_type=remediation_type,
        ),
        "estimate_note": (
            "Effort and disruption values are transparent rule-based "
            "estimates and should be validated by the implementation team."
        ),
    }