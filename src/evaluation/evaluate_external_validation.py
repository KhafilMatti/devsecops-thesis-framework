from pathlib import Path
import json
import pandas as pd

# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
        PROJECT_ROOT
        / "external_validation"
        / "results"
        / "external_validation_framework_results.json"
)

OUTPUT_DIR = (
        PROJECT_ROOT
        / "external_validation"
        / "results"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# LOAD RESULTS
# ============================================================

print("=" * 65)
print("EXTERNAL VALIDATION EVALUATION")
print("=" * 65)

with INPUT_FILE.open("r", encoding="utf-8") as f:
    results = json.load(f)

print(f"\nLoaded {len(results)} framework results.")


# ============================================================
# EXTRACT FIELDS
# ============================================================

rows = []

for result in results:

    external = result.get("external_validation", {})

    rows.append({
        "cve_id": external.get("cve_id"),
        "cvss_score": external.get("cvss_score"),
        "epss_score": external.get("epss_score"),
        "epss_percentile": external.get("epss_percentile"),
        "cisa_kev": external.get("cisa_kev", False),

        "base_priority": result.get("priority_level"),
        "base_risk_score": result.get("risk_score"),

        "adjusted_priority": result.get(
            "exploitability_adjusted_priority"
        ),
        "adjusted_score": result.get(
            "exploitability_adjusted_score"
        ),
    })

df = pd.DataFrame(rows)


# ============================================================
# CHECK DATA
# ============================================================

print("\nDataset checks:")
print(f"Total CVEs: {len(df)}")
print(f"Unique CVEs: {df['cve_id'].nunique()}")
print(f"KEV: {df['cisa_kev'].sum()}")
print(f"Non-KEV: {(~df['cisa_kev']).sum()}")


# ============================================================
# PRIORITY NORMALISATION
# ============================================================

def priority_number(value):

    if value is None:
        return None

    value = str(value).upper()

    if "P1" in value:
        return 1
    if "P2" in value:
        return 2
    if "P3" in value:
        return 3
    if "P4" in value:
        return 4

    return None


df["base_priority_number"] = (
    df["base_priority"].apply(priority_number)
)

df["adjusted_priority_number"] = (
    df["adjusted_priority"].apply(priority_number)
)


# ============================================================
# 1. KEV PRIORITY DISTRIBUTION
# ============================================================

print("\n" + "=" * 65)
print("KEV VS NON-KEV — BASE PRIORITY")
print("=" * 65)

base_table = pd.crosstab(
    df["cisa_kev"],
    df["base_priority_number"]
)

print(base_table)


print("\n" + "=" * 65)
print("KEV VS NON-KEV — ADJUSTED PRIORITY")
print("=" * 65)

adjusted_table = pd.crosstab(
    df["cisa_kev"],
    df["adjusted_priority_number"]
)

print(adjusted_table)


# ============================================================
# 2. HIGH-PRIORITY KEV CAPTURE
# ============================================================

kev = df[df["cisa_kev"] == True]

base_kev_high = (
        kev["base_priority_number"] <= 2
).sum()

adjusted_kev_high = (
        kev["adjusted_priority_number"] <= 2
).sum()

base_capture = base_kev_high / len(kev)
adjusted_capture = adjusted_kev_high / len(kev)

print("\n" + "=" * 65)
print("CISA KEV CAPTURE AT P1/P2")
print("=" * 65)

print(
    f"Base framework: "
    f"{base_kev_high}/{len(kev)} "
    f"({base_capture:.2%})"
)

print(
    f"Adjusted framework: "
    f"{adjusted_kev_high}/{len(kev)} "
    f"({adjusted_capture:.2%})"
)


# ============================================================
# 3. EPSS BY PRIORITY
# ============================================================

print("\n" + "=" * 65)
print("MEAN EPSS BY BASE PRIORITY")
print("=" * 65)

print(
    df.groupby("base_priority_number")
    ["epss_score"]
    .mean()
)


print("\n" + "=" * 65)
print("MEAN EPSS BY ADJUSTED PRIORITY")
print("=" * 65)

print(
    df.groupby("adjusted_priority_number")
    ["epss_score"]
    .mean()
)


# ============================================================
# 4. CVSS BY PRIORITY
# ============================================================

print("\n" + "=" * 65)
print("MEAN CVSS BY BASE PRIORITY")
print("=" * 65)

print(
    df.groupby("base_priority_number")
    ["cvss_score"]
    .mean()
)


# ============================================================
# 5. KEV VS NON-KEV SCORE COMPARISON
# ============================================================

print("\n" + "=" * 65)
print("KEV VS NON-KEV MEAN SCORES")
print("=" * 65)

score_comparison = (
    df.groupby("cisa_kev")
    [
        [
            "cvss_score",
            "epss_score",
            "base_risk_score",
            "adjusted_score"
        ]
    ]
    .mean()
)

print(score_comparison)


# ============================================================
# 6. PRIORITY MOVEMENT
# ============================================================

df["priority_change"] = (
        df["adjusted_priority_number"]
        - df["base_priority_number"]
)

print("\n" + "=" * 65)
print("PRIORITY MOVEMENT AFTER EXPLOITABILITY ADJUSTMENT")
print("=" * 65)

print(
    df["priority_change"]
    .value_counts()
    .sort_index()
)

print("\nInterpretation:")
print("Negative = moved to HIGHER priority")
print("0        = unchanged")
print("Positive = moved to LOWER priority")


# ============================================================
# 7. SAVE RESULTS
# ============================================================

df.to_csv(
    OUTPUT_DIR / "external_validation_analysis.csv",
    index=False
)

base_table.to_csv(
    OUTPUT_DIR / "kev_base_priority_distribution.csv"
)

adjusted_table.to_csv(
    OUTPUT_DIR / "kev_adjusted_priority_distribution.csv"
)

score_comparison.to_csv(
    OUTPUT_DIR / "kev_score_comparison.csv"
)


summary = {
    "total_cves": len(df),
    "kev_count": int(df["cisa_kev"].sum()),
    "non_kev_count": int((~df["cisa_kev"]).sum()),

    "base_kev_p1_p2": int(base_kev_high),
    "base_kev_capture_rate": float(base_capture),

    "adjusted_kev_p1_p2": int(adjusted_kev_high),
    "adjusted_kev_capture_rate": float(adjusted_capture),
}

with (
        OUTPUT_DIR
        / "external_validation_summary.json"
).open("w", encoding="utf-8") as f:

    json.dump(summary, f, indent=2)


print("\n" + "=" * 65)
print("EXTERNAL VALIDATION EVALUATION COMPLETE")
print("=" * 65)

print("\nSaved:")
print("- external_validation_analysis.csv")
print("- kev_base_priority_distribution.csv")
print("- kev_adjusted_priority_distribution.csv")
print("- kev_score_comparison.csv")
print("- external_validation_summary.json")