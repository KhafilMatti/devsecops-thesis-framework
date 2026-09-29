import json
from pathlib import Path
from typing import Any

INPUT_FILE = Path("data/gitlab_trivy_raw.json")
OUTPUT_FILE = Path("data/normalised_gitlab_events.json")

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
}


def extract_cvss(vulnerability: dict[str, Any]
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
    cvss_score, cvss_vector = extract_cvss(vulnerability)

    return {
        "event_id": f"gitlab-trivy-{event_number}",
        "source_platform": "GitLab",
        "source_tool": "Trivy",
        "event_type": "dependency_vulnerability",
        "title": (
                vulnerability.get("Title")
                or vulnerability.get("VulnerabilityID")
                or "Untitled vulnerability"
        ),
        "description": vulnerability.get("Description"),
        "severity": SEVERITY_MAP.get(
            str(vulnerability.get("Severity", "UNKNOWN")).upper(),
            "unknown",
        ),
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
    }


def main() -> None:
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Trivy report not found at {INPUT_FILE}. "
            "Copy the downloaded report into the data folder first."
        )

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        report = json.load(file)

    results = report.get("Results") or []
    normalised_events: list[dict[str, Any]] = []
    event_number = 1

    for result in results:
        target = result.get("Target")
        vulnerabilities = result.get("Vulnerabilities") or []

        for vulnerability in vulnerabilities:
            normalised_events.append(
                normalise_vulnerability(
                    vulnerability=vulnerability,
                    target=target,
                    event_number=event_number,
                )
            )
            event_number += 1

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(normalised_events, file, indent=4)

    print(f"Normalised {len(normalised_events)} GitLab/Trivy events")
    print(f"Saved output to {OUTPUT_FILE}")

    for event in normalised_events:
        print("-" * 70)
        print("Event ID:", event["event_id"])
        print("Platform:", event["source_platform"])
        print("Tool:", event["source_tool"])
        print("CVE:", event["cve_id"])
        print("Severity:", event["severity"])
        print("Package:", event["package_name"])
        print("Installed version:", event["installed_version"])
        print("Patched version:", event["patched_version"])
        print("CVSS:", event["cvss_score"])


if __name__ == "__main__":
    main()