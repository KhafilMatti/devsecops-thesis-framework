import copy
from typing import Any


def normalise_text(value: Any) -> str:
    """Convert optional values into lower case searchable text."""
    return str(value or "").strip().lower()


def get_event_path(event: dict[str, Any]) -> str:
    """Return the most appropriate file or resource path for an event."""
    return normalise_text(
        event.get("manifest_path")
        or event.get("resource_path")
        or event.get("target")
        or ""
    )


def build_searchable_text(event: dict[str, Any]) -> str:
    """
    Combine the event fields that may provide useful context indicators.
    """
    values = (
        event.get("title"),
        event.get("description"),
        event.get("manifest_path"),
        event.get("resource_path"),
        event.get("package_name"),
        event.get("source_platform"),
        event.get("source_tool"),
        event.get("repository_name"),
        event.get("project_name"),
    )

    return " ".join(
        normalise_text(value)
        for value in values
        if value
    )


def matches_rule(
        event: dict[str, Any],
        rule: dict[str, Any],
) -> tuple[bool, list[str]]:
    """
    Determine whether an event satisfies a context-assignment rule.

    Different condition groups use AND logic. Values within one group
    use OR logic.
    """
    conditions = rule.get("conditions") or {}

    event_path = get_event_path(event)
    searchable_text = build_searchable_text(event)
    event_type = normalise_text(event.get("event_type"))
    platform = normalise_text(event.get("source_platform"))
    tool = normalise_text(event.get("source_tool"))

    matched_conditions: list[str] = []

    path_terms = [
        normalise_text(term)
        for term in conditions.get("path_contains", [])
    ]

    if path_terms:
        matched_path_terms = [
            term
            for term in path_terms
            if term in event_path
        ]

        if not matched_path_terms:
            return False, []

        matched_conditions.append(
            f"path contains: {', '.join(matched_path_terms)}"
        )

    keywords = [
        normalise_text(keyword)
        for keyword in conditions.get("keywords", [])
    ]

    if keywords:
        matched_keywords = [
            keyword
            for keyword in keywords
            if keyword in searchable_text
        ]

        if not matched_keywords:
            return False, []

        matched_conditions.append(
            f"keywords: {', '.join(matched_keywords)}"
        )

    allowed_event_types = {
        normalise_text(value)
        for value in conditions.get("event_types", [])
    }

    if allowed_event_types:
        if event_type not in allowed_event_types:
            return False, []

        matched_conditions.append(
            f"event type: {event_type}"
        )

    allowed_platforms = {
        normalise_text(value)
        for value in conditions.get("platforms", [])
    }

    if allowed_platforms:
        if platform not in allowed_platforms:
            return False, []

        matched_conditions.append(
            f"platform: {platform}"
        )

    allowed_tools = {
        normalise_text(value)
        for value in conditions.get("tools", [])
    }

    if allowed_tools:
        if tool not in allowed_tools:
            return False, []

        matched_conditions.append(
            f"tool: {tool}"
        )

    if not conditions:
        return False, []

    return True, matched_conditions


def calculate_assignment_confidence(
        matched_conditions: list[str],
) -> float:
    """
    Provide a transparent confidence value based on the amount of
    matching evidence.

    This is a rule match confidence score
    """
    condition_count = len(matched_conditions)

    if condition_count >= 3:
        return 1.0

    if condition_count == 2:
        return 0.9

    if condition_count == 1:
        return 0.75

    return 0.0


def resolve_asset_context(
        event: dict[str, Any],
        static_profiles: dict[str, Any],
        rule_configuration: dict[str, Any],
) -> dict[str, Any]:
    """
    Automatically resolve an event's asset context.

    Rules are evaluated by descending priority. If no automatic rule
    matches, the existing static path based profile is used.
    """
    rules = rule_configuration.get("rules") or []

    ordered_rules = sorted(
        rules,
        key=lambda rule: int(rule.get("priority", 0)),
        reverse=True,
    )

    for rule in ordered_rules:
        matched, matched_conditions = matches_rule(
            event,
            rule,
        )

        if not matched:
            continue

        profile = copy.deepcopy(rule.get("profile") or {})

        profile.update(
            {
                "asset_path": get_event_path(event),
                "context_profile": rule.get("rule_id"),
                "context_assignment_method": "automatic_rule",
                "context_rule_id": rule.get("rule_id"),
                "context_rule_description": rule.get(
                    "description"
                ),
                "context_match_evidence": matched_conditions,
                "context_assignment_confidence": (
                    calculate_assignment_confidence(
                        matched_conditions
                    )
                ),
            }
        )

        return profile

    event_path = get_event_path(event)

    selected_profile_name = (
        event_path
        if event_path in static_profiles
        else "default"
    )

    static_profile = copy.deepcopy(
        static_profiles.get(selected_profile_name)
        or static_profiles.get("default")
        or {}
    )

    static_profile.update(
        {
            "asset_path": event_path,
            "context_profile": selected_profile_name,
            "context_assignment_method": "static_fallback",
            "context_rule_id": None,
            "context_rule_description": None,
            "context_match_evidence": [],
            "context_assignment_confidence": 0.5,
        }
    )

    return static_profile