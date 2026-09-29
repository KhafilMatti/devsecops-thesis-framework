from pathlib import Path
import json
import pandas as pd


# =========================================================
# 1. PATHS
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
        PROJECT_ROOT
        / "external_validation"
        / "processed"
        / "external_validation_sample_100.csv"
)

OUTPUT_FILE = (
        PROJECT_ROOT
        / "external_validation"
        / "processed"
        / "external_validation_events.json"
)


# =========================================================
# 2. HELPERS
# =========================================================

def safe_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def safe_number(value, default=0.0):
    if pd.isna(value):
        return default

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalise_severity(value):
    severity = safe_text(value).upper()

    allowed = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    }

    if severity in allowed:
        return severity

    return "UNKNOWN"


def build_exploitability_context(row):
    """
    Build transparent text from real CVSS characteristics.

    The existing exploitability engine performs keyword-based analysis
    of event text. This function exposes genuine CVSS characteristics
    to that engine without using EPSS or CISA KEV.
    """

    parts = []

    attack_vector = safe_text(
        row.get("attack_vector")
    ).upper()

    attack_complexity = safe_text(
        row.get("attack_complexity")
    ).upper()

    privileges = safe_text(
        row.get("privileges_required")
    ).upper()

    user_interaction = safe_text(
        row.get("user_interaction")
    ).upper()


    if attack_vector == "NETWORK":
        parts.append(
            "The vulnerability can be exploited over a network."
        )

    elif attack_vector == "LOCAL":
        parts.append(
            "Local access is required to exploit the vulnerability."
        )

    elif attack_vector == "ADJACENT_NETWORK":
        parts.append(
            "The vulnerability requires adjacent network access."
        )

    elif attack_vector == "PHYSICAL":
        parts.append(
            "Physical access is required to exploit the vulnerability."
        )


    if attack_complexity == "LOW":
        parts.append(
            "The attack has low attack complexity."
        )

    elif attack_complexity == "HIGH":
        parts.append(
            "The attack has high attack complexity."
        )


    if privileges == "NONE":
        parts.append(
            "No authentication or elevated privileges are required."
        )

    elif privileges == "LOW":
        parts.append(
            "The attack requires low privileges."
        )

    elif privileges == "HIGH":
        parts.append(
            "Elevated privileges are required."
        )


    if user_interaction == "NONE":
        parts.append(
            "No user interaction is required."
        )

    elif user_interaction == "REQUIRED":
        parts.append(
            "User interaction is required."
        )


    return " ".join(parts)

def safe_bool(value):
    if isinstance(value, bool):
        return value

    text = safe_text(value).lower()

    if text in {"true", "1", "yes", "y"}:
        return True

    if text in {"false", "0", "no", "n"}:
        return False

    return False

# =========================================================
# 3. LOAD FROZEN SAMPLE
# =========================================================

print("=" * 70)
print("PREPARING EXTERNAL VALIDATION EVENTS")
print("=" * 70)

df = pd.read_csv(
    INPUT_FILE,
    low_memory=False
)

print(f"\nLoaded {len(df)} frozen CVE records.")


if len(df) != 100:
    raise ValueError(
        f"Expected exactly 100 external CVEs, found {len(df)}."
    )


# =========================================================
# 4. CONVERT CVEs TO FRAMEWORK EVENTS
# =========================================================

events = []


for _, row in df.iterrows():

    validation_id = safe_text(
        row.get("validation_id")
    )

    cve_id = safe_text(
        row.get("cve_id")
    )

    original_description = safe_text(
        row.get("description")
    )

    technical_context = build_exploitability_context(row)

    if original_description:
        combined_description = (
            f"{original_description} "
            f"{technical_context}"
        ).strip()
    else:
        combined_description = technical_context


    event = {

        # -------------------------------------------------
        # Framework identifiers
        # -------------------------------------------------

        "event_id": validation_id,

        "title": f"External validation vulnerability {cve_id}",

        "event_type": "dependency_vulnerability",

        "source_platform": "external_validation",

        "source_tool": "NVD_CVE_dataset",

        "repository_name": "external-validation",

        "project_name": "external-validation",


        # -------------------------------------------------
        # Vulnerability information consumed by framework
        # -------------------------------------------------

        "severity": normalise_severity(
            row.get("base_severity")
        ),

        "cvss_score": safe_number(
            row.get("base_score")
        ),

        "description": combined_description,

        "message": combined_description,

        "resolution": "",

        "patched_version": "",

        "package_name": "",


        # -------------------------------------------------
        # Fixed path forces consistent context fallback
        # -------------------------------------------------

        "resource_path": (
            f"external-validation/{cve_id}"
        ),

        "manifest_path": (
            f"external-validation/{cve_id}"
        ),


        # -------------------------------------------------
        # Preserve external evidence.
        #
        # These fields are retained for evaluation only.
        # They MUST NOT be consumed by the prioritisation
        # algorithm.
        # -------------------------------------------------

        "external_validation": {

            "cve_id": cve_id,

            "cvss_score": safe_number(
                row.get("base_score")
            ),

            "base_severity": safe_text(
                row.get("base_severity")
            ),

            "epss_score": safe_number(
                row.get("epss_score")
            ),

            "epss_percentile": safe_number(
                row.get("epss_perc")
            ),

            "cisa_kev": safe_bool(
                row.get("cisa_kev")
            ),

            "attack_vector": safe_text(
                row.get("attack_vector")
            ),

            "attack_complexity": safe_text(
                row.get("attack_complexity")
            ),

            "privileges_required": safe_text(
                row.get("privileges_required")
            ),

            "user_interaction": safe_text(
                row.get("user_interaction")
            ),

            "impact_score": safe_number(
                row.get("impact_score")
            ),

            "exploitability_score_source": safe_number(
                row.get("exploitability_score")
            ),

            "published_date": safe_text(
                row.get("published_date")
            ),


        },
    }
    events.append(event)

if len(events) != 100:
    raise ValueError(
        f"Expected 100 generated events, but created {len(events)}."
    )

# =========================================================
# 5. SAVE
# =========================================================
OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
) as file:
    json.dump(
        events,
        file,
        indent=2
    )

print(f"\nActually wrote {len(events)} events to:")
print(OUTPUT_FILE)

with OUTPUT_FILE.open(
        "r",
        encoding="utf-8"
) as file:
    verify_events = json.load(file)

print(
    "Verified events written to disk:",
    len(verify_events)
)

if len(verify_events) != 100:
    raise ValueError(
        f"File write verification failed: "
        f"expected 100 events but file contains {len(verify_events)}."
    )


# =========================================================
# 6. CHECKS
# =========================================================

print("\nValidation checks:")

print(
    "Events created:",
    len(events)
)

print(
    "Unique event IDs:",
    len(
        {
            event["event_id"]
            for event in events
        }
    )
)

print(
    "Unique CVEs:",
    len(
        {
            event["external_validation"]["cve_id"]
            for event in events
        }
    )
)


kev_count = sum(
    1
    for event in events
    if event["external_validation"]["cisa_kev"]
)

print(
    "CISA KEV records:",
    kev_count
)

print(
    "Non-KEV records:",
    len(events) - kev_count
)


# =========================================================
# 7. DISPLAY SAMPLE EVENT
# =========================================================

print("\nExample generated event:\n")

print(
    json.dumps(
        events[0],
        indent=2
    )
)


print("\n" + "=" * 70)
print("EXTERNAL VALIDATION EVENTS READY")
print("=" * 70)

print(f"\nSaved to:\n{OUTPUT_FILE}")