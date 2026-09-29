import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

ENRICHED_EVENTS_FILE = Path("data/enriched_events.json")
SECTOR_CONTEXT_FILE = Path("data/sector_context.json")

JSON_OUTPUT_FILE = Path(
    "data/sector_prioritisation_results.json"
)
CSV_OUTPUT_FILE = Path(
    "data/sector_prioritisation_summary.csv"
)

TECHNICAL_WEIGHT = 0.70
SECTOR_WEIGHT = 0.30

STRIDE_ALIGNMENT_WEIGHT = 0.50
BUSINESS_IMPACT_WEIGHT = 0.50

IMPACT_LEVEL_VALUES = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.25,
    "none": 0.0,
}

BUSINESS_IMPACT_DIMENSIONS = (
    "safety_impact",
    "operational_disruption",
    "financial_loss",
    "regulatory_exposure",
    "reputational_damage",
)

# This table defines which business consequences are most associated
# with each STRIDE category. Values range from 0.0 to 1.0.
STRIDE_BUSINESS_IMPACT_MAP = {
    "Spoofing": {
        "safety_impact": 0.2,
        "operational_disruption": 0.4,
        "financial_loss": 0.9,
        "regulatory_exposure": 0.7,
        "reputational_damage": 0.7,
    },
    "Tampering": {
        "safety_impact": 0.8,
        "operational_disruption": 0.9,
        "financial_loss": 0.8,
        "regulatory_exposure": 0.7,
        "reputational_damage": 0.8,
    },
    "Repudiation": {
        "safety_impact": 0.2,
        "operational_disruption": 0.4,
        "financial_loss": 0.7,
        "regulatory_exposure": 0.9,
        "reputational_damage": 0.6,
    },
    "Information Disclosure": {
        "safety_impact": 0.3,
        "operational_disruption": 0.4,
        "financial_loss": 0.8,
        "regulatory_exposure": 1.0,
        "reputational_damage": 0.9,
    },
    "Denial of Service": {
        "safety_impact": 0.9,
        "operational_disruption": 1.0,
        "financial_loss": 0.7,
        "regulatory_exposure": 0.4,
        "reputational_damage": 0.8,
    },
    "Elevation of Privilege": {
        "safety_impact": 0.8,
        "operational_disruption": 0.9,
        "financial_loss": 0.9,
        "regulatory_exposure": 0.8,
        "reputational_damage": 0.8,
    },
    "Unclassified": {
        "safety_impact": 0.2,
        "operational_disruption": 0.4,
        "financial_loss": 0.3,
        "regulatory_exposure": 0.3,
        "reputational_damage": 0.3,
    },
}


def load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(
            f"Required file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def finding_key(event: dict[str, Any]) -> str:
    """
    Use the existing cross-platform correlation identifier where
    available so that the same CVE is not listed twice.
    """
    return str(
        event.get("correlation_id")
        or event.get("event_id")
        or "unknown-finding"
    )


def aggregate_findings(
        events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Combine cross-platform records that refer to the same vulnerability.

    The highest-risk record becomes the representative event, while
    all source tools and event identifiers are retained.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        grouped[finding_key(event)].append(event)

    aggregated_findings: list[dict[str, Any]] = []

    for key, records in grouped.items():
        representative = max(
            records,
            key=lambda event: float(
                event.get("risk_score") or 0
            ),
        )

        finding = dict(representative)

        finding["finding_key"] = key
        finding["source_event_ids"] = sorted(
            str(record.get("event_id"))
            for record in records
        )
        finding["source_tools"] = sorted(
            {
                str(record.get("source_tool"))
                for record in records
            }
        )
        finding["source_platforms"] = sorted(
            {
                str(record.get("source_platform"))
                for record in records
            }
        )
        finding["correlated_record_count"] = len(records)

        aggregated_findings.append(finding)

    return aggregated_findings


def calculate_stride_alignment(
        event: dict[str, Any],
        sector_profile: dict[str, Any],
) -> tuple[float, list[dict[str, Any]]]:
    """
    Measure how strongly the event's STRIDE impacts align with the
    priorities defined for the sector.
    """
    categories = event.get("stride_categories") or [
        "Unclassified"
    ]

    weights = sector_profile.get("stride_weights") or {}

    category_details: list[dict[str, Any]] = []

    for category in categories:
        weight = float(
            weights.get(
                category,
                weights.get("Unclassified", 0),
            )
        )

        category_details.append(
            {
                "category": category,
                "sector_weight": weight,
            }
        )

    if not category_details:
        return 0.0, []

    mean_weight = sum(
        detail["sector_weight"]
        for detail in category_details
    ) / len(category_details)

    score = min((mean_weight / 10.0) * 100.0, 100.0)

    return round(score, 2), category_details


def derive_event_impact_applicability(
        stride_categories: list[str],
) -> dict[str, float]:
    """
    Derive the potential business consequences of the event from its
    STRIDE categories.

    Where several categories apply, the strongest applicability value
    for each business-impact dimension is retained.
    """
    categories = stride_categories or ["Unclassified"]

    applicability = {
        dimension: 0.0
        for dimension in BUSINESS_IMPACT_DIMENSIONS
    }

    for category in categories:
        category_impacts = STRIDE_BUSINESS_IMPACT_MAP.get(
            category,
            STRIDE_BUSINESS_IMPACT_MAP["Unclassified"],
        )

        for dimension in BUSINESS_IMPACT_DIMENSIONS:
            applicability[dimension] = max(
                applicability[dimension],
                float(category_impacts.get(dimension, 0.0)),
            )

    return applicability


def calculate_business_impact_alignment(
        event: dict[str, Any],
        sector_profile: dict[str, Any],
) -> tuple[float, list[dict[str, Any]]]:
    """
    Combine:
    - the asset's predefined impact level;
    - the event's STRIDE-derived impact applicability;
    - the sector's business-impact weighting.
    """
    asset_context = event.get("asset_context") or {}

    sector_weights = (
            sector_profile.get("business_impact_weights") or {}
    )

    applicability = derive_event_impact_applicability(
        event.get("stride_categories") or []
    )

    weighted_total = 0.0
    maximum_total = 0.0
    impact_details: list[dict[str, Any]] = []

    for dimension in BUSINESS_IMPACT_DIMENSIONS:
        sector_dimension_weight = float(
            sector_weights.get(dimension, 0)
        )

        asset_level = str(
            asset_context.get(dimension, "none")
        ).lower()

        asset_multiplier = IMPACT_LEVEL_VALUES.get(
            asset_level,
            0.0,
        )

        event_applicability = applicability.get(
            dimension,
            0.0,
        )

        contribution = (
                sector_dimension_weight
                * asset_multiplier
                * event_applicability
        )

        weighted_total += contribution
        maximum_total += sector_dimension_weight

        impact_details.append(
            {
                "dimension": dimension,
                "sector_weight": sector_dimension_weight,
                "asset_level": asset_level,
                "asset_multiplier": asset_multiplier,
                "event_applicability": round(
                    event_applicability,
                    2,
                ),
                "contribution": round(
                    contribution,
                    3,
                ),
            }
        )

    score = (
        (weighted_total / maximum_total) * 100.0
        if maximum_total > 0
        else 0.0
    )

    return round(min(score, 100.0), 2), impact_details


def assign_priority(score: float) -> str:
    if score >= 80:
        return "P1 - Immediate"

    if score >= 65:
        return "P2 - High"

    if score >= 45:
        return "P3 - Medium"

    return "P4 - Low"


def top_sector_factors(
        impact_details: list[dict[str, Any]],
        limit: int = 3,
) -> list[dict[str, Any]]:
    return sorted(
        impact_details,
        key=lambda item: item["contribution"],
        reverse=True,
    )[:limit]


def generate_sector_explanation(
        event: dict[str, Any],
        sector_profile: dict[str, Any],
        technical_score: float,
        stride_score: float,
        business_impact_score: float,
        sector_impact_score: float,
        final_score: float,
        stride_details: list[dict[str, Any]],
        impact_details: list[dict[str, Any]],
) -> dict[str, Any]:
    sector_name = sector_profile.get(
        "display_name",
        "Unknown sector",
    )

    reasons: list[str] = [
        (
            f"The existing context-aware technical risk score "
            f"is {technical_score:.2f}/100 and contributes "
            f"{TECHNICAL_WEIGHT * 100:.0f}% of the final score."
        ),
        (
            f"The {sector_name} sector-impact score is "
            f"{sector_impact_score:.2f}/100 and contributes "
            f"{SECTOR_WEIGHT * 100:.0f}% of the final score."
        ),
    ]

    if stride_details:
        strongest_stride = max(
            stride_details,
            key=lambda item: item["sector_weight"],
        )

        reasons.append(
            f"The event maps to {strongest_stride['category']}, "
            f"which has a sector weight of "
            f"{strongest_stride['sector_weight']}/10 for "
            f"{sector_name}."
        )

    for factor in top_sector_factors(impact_details):
        readable_dimension = factor["dimension"].replace(
            "_",
            " ",
        )

        reasons.append(
            f"{readable_dimension.title()} contributes to the "
            f"sector adjustment because the asset impact is "
            f"{factor['asset_level']} and the event applicability "
            f"is {factor['event_applicability']:.2f}."
        )

    if event.get("patched_version"):
        reasons.append(
            f"A patched version is available "
            f"({event['patched_version']})."
        )

    if event.get("resolution"):
        reasons.append(
            f"An actionable configuration remediation is available: "
            f"{event['resolution']}."
        )

    return {
        "summary": (
            f"For {sector_name}, this finding receives a final "
            f"sector-aware score of {final_score:.2f}/100."
        ),
        "reasons": reasons,
        "score_formula": {
            "technical_component": round(
                technical_score * TECHNICAL_WEIGHT,
                2,
                ),
            "sector_component": round(
                sector_impact_score * SECTOR_WEIGHT,
                2,
                ),
            "final_score": round(final_score, 2),
        },
        "subscores": {
            "technical_score": round(
                technical_score,
                2,
            ),
            "stride_alignment_score": round(
                stride_score,
                2,
            ),
            "business_impact_score": round(
                business_impact_score,
                2,
            ),
            "sector_impact_score": round(
                sector_impact_score,
                2,
            ),
        },
    }


def evaluate_finding_for_sector(
        event: dict[str, Any],
        sector_key: str,
        sector_profile: dict[str, Any],
) -> dict[str, Any]:
    technical_score = float(
        event.get("risk_score") or 0
    )

    stride_score, stride_details = (
        calculate_stride_alignment(
            event,
            sector_profile,
        )
    )

    business_impact_score, impact_details = (
        calculate_business_impact_alignment(
            event,
            sector_profile,
        )
    )

    sector_impact_score = (
            stride_score * STRIDE_ALIGNMENT_WEIGHT
            + business_impact_score * BUSINESS_IMPACT_WEIGHT
    )

    final_score = (
            technical_score * TECHNICAL_WEIGHT
            + sector_impact_score * SECTOR_WEIGHT
    )

    final_score = round(
        min(final_score, 100.0),
        2,
    )

    explanation = generate_sector_explanation(
        event=event,
        sector_profile=sector_profile,
        technical_score=technical_score,
        stride_score=stride_score,
        business_impact_score=business_impact_score,
        sector_impact_score=sector_impact_score,
        final_score=final_score,
        stride_details=stride_details,
        impact_details=impact_details,
    )

    return {
        "finding_key": event.get("finding_key"),
        "event_type": event.get("event_type"),
        "title": event.get("title"),
        "cve_id": event.get("cve_id"),
        "misconfiguration_id": event.get(
            "misconfiguration_id"
        ),
        "sector": sector_key,
        "sector_display_name": sector_profile.get(
            "display_name"
        ),
        "source_event_ids": event.get(
            "source_event_ids",
            [],
        ),
        "source_tools": event.get(
            "source_tools",
            [],
        ),
        "source_platforms": event.get(
            "source_platforms",
            [],
        ),
        "technical_score": technical_score,
        "stride_alignment_score": stride_score,
        "business_impact_score": business_impact_score,
        "sector_impact_score": round(
            sector_impact_score,
            2,
        ),
        "final_sector_score": final_score,
        "priority_level": assign_priority(final_score),
        "patched_version": event.get("patched_version"),
        "resolution": event.get("resolution"),
        "stride_categories": event.get(
            "stride_categories",
            [],
        ),
        "explanation": explanation,
        "impact_details": impact_details,
    }


def create_sector_rankings(
        findings: list[dict[str, Any]],
        sector_profiles: dict[str, Any],
) -> dict[str, Any]:
    sector_results: dict[str, Any] = {}

    for sector_key, sector_profile in sector_profiles.items():
        evaluated_findings = [
            evaluate_finding_for_sector(
                event=finding,
                sector_key=sector_key,
                sector_profile=sector_profile,
            )
            for finding in findings
        ]

        evaluated_findings.sort(
            key=lambda finding: (
                finding["final_sector_score"],
                finding["technical_score"],
                bool(
                    finding.get("patched_version")
                    or finding.get("resolution")
                ),
            ),
            reverse=True,
        )

        for rank, finding in enumerate(
                evaluated_findings,
                start=1,
        ):
            finding["sector_rank"] = rank

        sector_results[sector_key] = {
            "display_name": sector_profile.get(
                "display_name"
            ),
            "description": sector_profile.get(
                "description"
            ),
            "finding_count": len(evaluated_findings),
            "patch_queue": evaluated_findings,
        }

    return sector_results


def add_cross_sector_comparison(
        sector_results: dict[str, Any],
) -> list[dict[str, Any]]:
    comparison: dict[str, dict[str, Any]] = {}

    for sector_key, sector_data in sector_results.items():
        for finding in sector_data["patch_queue"]:
            key = finding["finding_key"]

            if key not in comparison:
                comparison[key] = {
                    "finding_key": key,
                    "title": finding["title"],
                    "cve_id": finding["cve_id"],
                    "misconfiguration_id": finding[
                        "misconfiguration_id"
                    ],
                    "sector_results": {},
                }

            comparison[key]["sector_results"][sector_key] = {
                "rank": finding["sector_rank"],
                "score": finding["final_sector_score"],
                "priority_level": finding["priority_level"],
            }

    output: list[dict[str, Any]] = []

    for finding in comparison.values():
        sector_values = finding["sector_results"]

        highest_sector = max(
            sector_values,
            key=lambda sector: sector_values[sector]["score"],
        )

        lowest_sector = min(
            sector_values,
            key=lambda sector: sector_values[sector]["score"],
        )

        highest_score = sector_values[highest_sector]["score"]
        lowest_score = sector_values[lowest_sector]["score"]

        finding["highest_impact_sector"] = highest_sector
        finding["lowest_impact_sector"] = lowest_sector
        finding["score_range"] = round(
            highest_score - lowest_score,
            2,
            )

        output.append(finding)

    output.sort(
        key=lambda finding: finding["score_range"],
        reverse=True,
    )

    return output


def write_csv(
        sector_results: dict[str, Any],
) -> None:
    CSV_OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "sector",
        "sector_display_name",
        "rank",
        "finding_key",
        "event_type",
        "title",
        "cve_id",
        "misconfiguration_id",
        "technical_score",
        "stride_alignment_score",
        "business_impact_score",
        "sector_impact_score",
        "final_sector_score",
        "priority_level",
        "source_tools",
    ]

    with CSV_OUTPUT_FILE.open(
            "w",
            encoding="utf-8",
            newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for sector_key, sector_data in sector_results.items():
            for finding in sector_data["patch_queue"]:
                writer.writerow(
                    {
                        "sector": sector_key,
                        "sector_display_name": finding[
                            "sector_display_name"
                        ],
                        "rank": finding["sector_rank"],
                        "finding_key": finding["finding_key"],
                        "event_type": finding["event_type"],
                        "title": finding["title"],
                        "cve_id": finding["cve_id"],
                        "misconfiguration_id": finding[
                            "misconfiguration_id"
                        ],
                        "technical_score": finding[
                            "technical_score"
                        ],
                        "stride_alignment_score": finding[
                            "stride_alignment_score"
                        ],
                        "business_impact_score": finding[
                            "business_impact_score"
                        ],
                        "sector_impact_score": finding[
                            "sector_impact_score"
                        ],
                        "final_sector_score": finding[
                            "final_sector_score"
                        ],
                        "priority_level": finding[
                            "priority_level"
                        ],
                        "source_tools": ", ".join(
                            finding["source_tools"]
                        ),
                    }
                )


def main() -> None:
    events = load_json(ENRICHED_EVENTS_FILE)
    sector_profiles = load_json(SECTOR_CONTEXT_FILE)

    if not isinstance(events, list):
        raise ValueError(
            f"{ENRICHED_EVENTS_FILE} must contain a JSON list."
        )

    if not isinstance(sector_profiles, dict):
        raise ValueError(
            f"{SECTOR_CONTEXT_FILE} must contain a JSON object."
        )

    findings = aggregate_findings(events)

    sector_results = create_sector_rankings(
        findings=findings,
        sector_profiles=sector_profiles,
    )

    cross_sector_comparison = add_cross_sector_comparison(
        sector_results
    )

    output = {
        "experiment": (
            "Experiment 5 - Sector-Aware Business Impact "
            "and Patch Prioritisation"
        ),
        "methodology": {
            "technical_weight": TECHNICAL_WEIGHT,
            "sector_weight": SECTOR_WEIGHT,
            "stride_alignment_weight": (
                STRIDE_ALIGNMENT_WEIGHT
            ),
            "business_impact_weight": BUSINESS_IMPACT_WEIGHT,
            "original_event_count": len(events),
            "unique_finding_count": len(findings),
            "sector_count": len(sector_profiles),
            "deduplication_method": (
                "Events sharing a correlation_id are combined into "
                "one patchable finding. Uncorrelated events retain "
                "their event_id."
            ),
        },
        "sector_rankings": sector_results,
        "cross_sector_comparison": cross_sector_comparison,
    }

    JSON_OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with JSON_OUTPUT_FILE.open(
            "w",
            encoding="utf-8",
    ) as file:
        json.dump(output, file, indent=4)

    write_csv(sector_results)

    print(
        "Experiment 5 - Sector-Aware Business Impact "
        "and Patch Prioritisation"
    )
    print("=" * 72)
    print(f"Original events loaded: {len(events)}")
    print(f"Unique findings after correlation: {len(findings)}")
    print(f"Sectors evaluated: {len(sector_profiles)}")

    for sector_key, sector_data in sector_results.items():
        print()
        print(
            f"{sector_data['display_name']} patch queue"
        )
        print("-" * 72)

        for finding in sector_data["patch_queue"][:5]:
            identifier = (
                    finding.get("cve_id")
                    or finding.get("misconfiguration_id")
                    or finding.get("finding_key")
            )

            print(
                f"{finding['sector_rank']}. "
                f"{identifier} | "
                f"{finding['final_sector_score']:.2f} | "
                f"{finding['priority_level']}"
            )
            print(
                f"   {finding['title']}"
            )

    print()
    print(f"Saved JSON results to {JSON_OUTPUT_FILE}")
    print(f"Saved CSV summary to {CSV_OUTPUT_FILE}")


if __name__ == "__main__":
    main()