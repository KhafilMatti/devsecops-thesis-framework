import json
from collections import Counter
from pathlib import Path
from typing import Any

GITHUB_FILE = Path("data/normalised_events.json")
GITLAB_FILE = Path("data/normalised_gitlab_experiment2_events.json")
OUTPUT_FILE = Path("data/all_normalised_events.json")

REQUIRED_FIELDS = {
    "event_id",
    "source_platform",
    "source_tool",
    "event_type",
    "title",
    "severity",
    "cve_id",
    "package_name",
    "cvss_score",
}


def load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Required input file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list of events.")

    return data


def validate_event(
        event: dict[str, Any],
        source_file: Path,
        event_index: int,
) -> list[str]:
    missing_fields = sorted(REQUIRED_FIELDS - event.keys())

    if not missing_fields:
        return []

    return [
        f"{source_file}, event index {event_index}: "
        f"missing {', '.join(missing_fields)}"
    ]


def add_correlation_fields(
        events: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    correlation_counts = Counter(
        (
            event.get("cve_id"),
            event.get("package_name"),
        )
        for event in events
        if event.get("cve_id")
    )

    enriched_events = []

    for event in events:
        event_copy = dict(event)

        cve_id = event_copy.get("cve_id")
        package_name = event_copy.get("package_name")

        if cve_id:
            event_copy["correlation_id"] = (
                f"{cve_id}:{package_name or 'unknown-package'}"
            )
            event_copy["cross_platform_match"] = (
                    correlation_counts[(cve_id, package_name)] > 1
            )
        else:
            event_copy["correlation_id"] = None
            event_copy["cross_platform_match"] = False

        enriched_events.append(event_copy)

    return enriched_events


def main() -> None:
    github_events = load_events(GITHUB_FILE)
    gitlab_events = load_events(GITLAB_FILE)

    validation_errors: list[str] = []

    for source_file, events in (
            (GITHUB_FILE, github_events),
            (GITLAB_FILE, gitlab_events),
    ):
        for index, event in enumerate(events):
            validation_errors.extend(
                validate_event(event, source_file, index)
            )

    if validation_errors:
        print("Schema validation failed:")

        for error in validation_errors:
            print("-", error)

        raise SystemExit(1)

    merged_events = github_events + gitlab_events
    merged_events = add_correlation_fields(merged_events)

    merged_events.sort(
        key=lambda event: float(event.get("cvss_score") or 0),
        reverse=True,
    )



    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(merged_events, file, indent=4)

    platform_counts = Counter(
        event.get("source_platform", "Unknown")
        for event in merged_events
    )
    event_type_counts = Counter(
        event.get("event_type", "unknown")
        for event in merged_events

    )


    matched_events = sum(
        1
        for event in merged_events
        if event.get("cross_platform_match")
    )

    print(f"GitHub events loaded: {len(github_events)}")
    print(f"GitLab events loaded: {len(gitlab_events)}")
    print(f"Total merged events: {len(merged_events)}")
    print(f"Cross-platform matched records: {matched_events}")
    print(f"Saved output to {OUTPUT_FILE}")

    print("\nEvents by platform:")

    for platform, count in sorted(platform_counts.items()):
        print(f"- {platform}: {count}")

    print("\nEvents by type:")

    for event_type, count in sorted(event_type_counts.items()):
        print(f"- {event_type}: {count}")

        print("\nSample merged events:")

    for event in merged_events[:5]:
        print("-" * 70)
        print("Event ID:", event.get("event_id"))
        print("Platform:", event.get("source_platform"))
        print("Tool:", event.get("source_tool"))
        print("CVE:", event.get("cve_id"))
        print("CVSS:", event.get("cvss_score"))
        print(
            "Cross-platform match:",
            event.get("cross_platform_match"),
        )


if __name__ == "__main__":
    main()