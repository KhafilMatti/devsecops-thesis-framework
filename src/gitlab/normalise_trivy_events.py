import json
from pathlib import Path
from typing import Any

# Experiment 2 Trivy report containing vulnerabilities and misconfigurations.
INPUT_FILE = Path("data/gitlab_trivy_experiment2_raw.json")

# Keep Experiment 2 output separate from the original Experiment 1 output.
OUTPUT_FILE = Path("data/normalised_gitlab_experiment2_events.json")

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
}


def normalise_severity(value: Any) -> str:
    """Convert Trivy severity labels into the framework's lowercase format."""
    return SEVERITY_MAP.get(
        str(value or "UNKNOWN").upper(),
        "unknown",
    )


def extract_cvss(
        vulnerability: dict[str, Any],
) -> tuple[float, str | None]:
    """
    Prefer the newest available CVSS generation:
    v4 first, then v3, then v2.

    Where several sources provide the same generation,
    use the highest score within that generation.
    """
    cvss_data = vulnerability.get("CVSS") or {}

    version_fields = (
        ("V40Score", "V40Vector"),
        ("V3Score", "V3Vector"),
        ("V2Score", "V2Vector"),
    )

    for score_field, vector_field in version_fields:
        candidates: list[tuple[float, str | None]] = []

        for source_data in cvss_data.values():
            score = source_data.get(score_field)

            if isinstance(score, (int, float)):
                candidates.append(
                    (
                        float(score),
                        source_data.get(vector_field),
                    )
                )

        if candidates:
            return max(candidates, key=lambda item: item[0])

    return 0.0, None


def extract_ghsa_id(vulnerability: dict[str, Any]) -> str | None:
    """Return the first GHSA identifier supplied by Trivy."""
    vendor_ids = vulnerability.get("VendorIDs") or []

    return next(
        (
            identifier
            for identifier in vendor_ids
            if str(identifier).startswith("GHSA-")
        ),
        None,
    )


def normalise_vulnerability(
        vulnerability: dict[str, Any],
        target: str | None,
        event_number: int,
) -> dict[str, Any]:
    """Convert a Trivy dependency vulnerability into the common event schema."""
    cvss_score, cvss_vector = extract_cvss(vulnerability)

    return {
        "event_id": f"gitlab-trivy-vuln-{event_number}",
        "source_platform": "GitLab",
        "source_tool": "Trivy",
        "event_type": "dependency_vulnerability",
        "title": (
                vulnerability.get("Title")
                or vulnerability.get("VulnerabilityID")
                or "Untitled vulnerability"
        ),
        "description": vulnerability.get("Description"),
        "severity": normalise_severity(vulnerability.get("Severity")),
        "cve_id": vulnerability.get("VulnerabilityID"),
        "ghsa_id": extract_ghsa_id(vulnerability),
        "package_name": vulnerability.get("PkgName"),
        "package_ecosystem": "maven",
        "manifest_path": target,
        "installed_version": vulnerability.get("InstalledVersion"),
        "vulnerable_version_range": None,
        "patched_version": vulnerability.get("FixedVersion") or None,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_ids": vulnerability.get("CweIDs") or [],
        "state": "open",
        "vulnerability_status": vulnerability.get("Status"),
        "published_at": vulnerability.get("PublishedDate"),
        "last_modified_at": vulnerability.get("LastModifiedDate"),
        "created_at": None,
        "fixed_at": None,
        "dismissed_at": None,
        "raw_url": vulnerability.get("PrimaryURL"),

        # Misconfiguration fields remain empty for vulnerability events.
        "misconfiguration_id": None,
        "misconfiguration_type": None,
        "resource_path": target,
        "resolution": None,
        "message": None,
        "status": vulnerability.get("Status"),
        "start_line": None,
        "end_line": None,
    }


def normalise_misconfiguration(
        misconfiguration: dict[str, Any],
        target: str | None,
        event_number: int,
) -> dict[str, Any]:
    """Convert a Trivy configuration finding into the common event schema."""
    cause_metadata = misconfiguration.get("CauseMetadata") or {}

    return {
        "event_id": f"gitlab-trivy-misconfig-{event_number}",
        "source_platform": "GitLab",
        "source_tool": "Trivy",
        "event_type": "misconfiguration",
        "title": (
                misconfiguration.get("Title")
                or misconfiguration.get("ID")
                or "Untitled misconfiguration"
        ),
        "description": misconfiguration.get("Description"),
        "severity": normalise_severity(misconfiguration.get("Severity")),

        # Vulnerability-specific fields remain empty to preserve the schema.
        "cve_id": None,
        "ghsa_id": None,
        "package_name": None,
        "package_ecosystem": None,
        "manifest_path": target,
        "installed_version": None,
        "vulnerable_version_range": None,
        "patched_version": None,
        "cvss_score": 0.0,
        "cvss_vector": None,
        "cwe_ids": [],
        "state": "open",
        "vulnerability_status": None,
        "published_at": None,
        "last_modified_at": None,
        "created_at": None,
        "fixed_at": None,
        "dismissed_at": None,
        "raw_url": misconfiguration.get("PrimaryURL"),

        # Misconfiguration-specific fields.
        "misconfiguration_id": misconfiguration.get("ID"),
        "misconfiguration_type": misconfiguration.get("Type"),
        "resource_path": target,
        "resolution": misconfiguration.get("Resolution"),
        "message": misconfiguration.get("Message"),
        "status": misconfiguration.get("Status"),
        "start_line": cause_metadata.get("StartLine"),
        "end_line": cause_metadata.get("EndLine"),
    }


def main() -> None:
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Trivy report not found at {INPUT_FILE}. "
            "Copy the Experiment 2 report into the data folder first."
        )

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        report = json.load(file)

    results = report.get("Results") or []
    normalised_events: list[dict[str, Any]] = []

    vulnerability_number = 1
    misconfiguration_number = 1

    for result in results:
        target = result.get("Target")

        vulnerabilities = result.get("Vulnerabilities") or []

        for vulnerability in vulnerabilities:
            normalised_events.append(
                normalise_vulnerability(
                    vulnerability=vulnerability,
                    target=target,
                    event_number=vulnerability_number,
                )
            )
            vulnerability_number += 1

        misconfigurations = result.get("Misconfigurations") or []

        for misconfiguration in misconfigurations:
            normalised_events.append(
                normalise_misconfiguration(
                    misconfiguration=misconfiguration,
                    target=target,
                    event_number=misconfiguration_number,
                )
            )
            misconfiguration_number += 1

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(normalised_events, file, indent=4)

    vulnerability_count = sum(
        event["event_type"] == "dependency_vulnerability"
        for event in normalised_events
    )

    misconfiguration_count = sum(
        event["event_type"] == "misconfiguration"
        for event in normalised_events
    )

    print(f"Normalised {len(normalised_events)} GitLab/Trivy events")
    print(f"Dependency vulnerabilities: {vulnerability_count}")
    print(f"Misconfigurations: {misconfiguration_count}")
    print(f"Saved output to {OUTPUT_FILE}")

    for event in normalised_events:
        print("-" * 70)
        print("Event ID:", event["event_id"])
        print("Event type:", event["event_type"])
        print("Platform:", event["source_platform"])
        print("Tool:", event["source_tool"])
        print("Severity:", event["severity"])
        print("Title:", event["title"])

        if event["event_type"] == "dependency_vulnerability":
            print("CVE:", event["cve_id"])
            print("Package:", event["package_name"])
            print("Installed version:", event["installed_version"])
            print("Patched version:", event["patched_version"])
            print("CVSS:", event["cvss_score"])

        elif event["event_type"] == "misconfiguration":
            print("Misconfiguration ID:", event["misconfiguration_id"])
            print("Resource:", event["resource_path"])
            print("Status:", event["status"])
            print("Resolution:", event["resolution"])
            print("Start line:", event["start_line"])


if __name__ == "__main__":
    main()