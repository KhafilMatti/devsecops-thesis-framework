from pathlib import Path
import json

import pandas as pd
from scipy.stats import fisher_exact, spearmanr


# ============================================================
# 1. PATHS
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
# 2. LOAD RESULTS
# ============================================================

print("=" * 65)
print("STATISTICAL EXTERNAL VALIDATION")
print("=" * 65)

print(f"\nReading:\n{INPUT_FILE}")

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

# Handle either a direct list or a wrapper object.
if isinstance(data, list):
    results = data
elif isinstance(data, dict):
    if "results" in data:
        results = data["results"]
    else:
        raise ValueError(
            "JSON is a dictionary but no 'results' key was found."
        )
else:
    raise ValueError("Unexpected JSON structure.")

print(f"\nLoaded {len(results)} framework results.")

if len(results) != 100:
    raise ValueError(
        f"Expected 100 external-validation results, found {len(results)}."
    )


# ============================================================
# 3. EXTRACT VALIDATION VARIABLES
# ============================================================

rows = []

for item in results:

    external = item.get("external_validation", {})

    cisa_kev = external.get("cisa_kev")
    epss_score = external.get("epss_score")

    # Framework priority fields from external validation results
    base_priority = item.get("priority_level")

    adjusted_priority = item.get(
        "exploitability_adjusted_priority"
    )

    base_priority_number = None
    adjusted_priority_number = None

    # Convert strings such as "P2 - High" if necessary.
    if base_priority_number is None and isinstance(base_priority, str):
        if base_priority.startswith("P1"):
            base_priority_number = 1
        elif base_priority.startswith("P2"):
            base_priority_number = 2
        elif base_priority.startswith("P3"):
            base_priority_number = 3
        elif base_priority.startswith("P4"):
            base_priority_number = 4

    if adjusted_priority_number is None and isinstance(adjusted_priority, str):
        if adjusted_priority.startswith("P1"):
            adjusted_priority_number = 1
        elif adjusted_priority.startswith("P2"):
            adjusted_priority_number = 2
        elif adjusted_priority.startswith("P3"):
            adjusted_priority_number = 3
        elif adjusted_priority.startswith("P4"):
            adjusted_priority_number = 4

    rows.append(
        {
            "cve_id": external.get("cve_id"),
            "cisa_kev": cisa_kev,
            "epss_score": epss_score,
            "base_priority_number": base_priority_number,
            "adjusted_priority_number": adjusted_priority_number,
        }
    )


df = pd.DataFrame(rows)

print("\nExtracted dataset:")
print(df.head())


# ============================================================
# 4. DATA VALIDATION
# ============================================================

required_columns = [
    "cisa_kev",
    "epss_score",
    "base_priority_number",
]

for column in required_columns:
    missing = df[column].isna().sum()

    print(f"Missing {column}: {missing}")

    if missing > 0:
        raise ValueError(
            f"Cannot continue: {column} contains {missing} missing values."
        )

df["cisa_kev"] = df["cisa_kev"].astype(bool)
df["epss_score"] = pd.to_numeric(df["epss_score"])
df["base_priority_number"] = pd.to_numeric(
    df["base_priority_number"]
)

print("\nKEV distribution:")
print(df["cisa_kev"].value_counts())


# ============================================================
# 5. HIGH-PRIORITY CLASSIFICATION
# ============================================================

# P1 and P2 represent high-priority vulnerabilities.
df["base_high_priority"] = (
        df["base_priority_number"] <= 2
)

print("\n" + "=" * 65)
print("KEV VS BASE HIGH PRIORITY")
print("=" * 65)

table = pd.crosstab(
    df["cisa_kev"],
    df["base_high_priority"]
)

# Force consistent False/True ordering.
table = table.reindex(
    index=[False, True],
    columns=[False, True],
    fill_value=0
)

print(table)


# ============================================================
# 6. FISHER'S EXACT TEST
# ============================================================

# Table arrangement:
#
#                 Not P1/P2     P1/P2
# Non-KEV
# KEV

odds_ratio, fisher_p = fisher_exact(
    table.values
)

print("\n" + "=" * 65)
print("FISHER'S EXACT TEST")
print("=" * 65)

print(f"Odds ratio: {odds_ratio:.4f}")
print(f"P-value:    {fisher_p:.10f}")

if fisher_p < 0.05:
    print(
        "Result: statistically significant association "
        "between KEV status and high framework priority."
    )
else:
    print(
        "Result: no statistically significant association "
        "at alpha = 0.05."
    )


# ============================================================
# 7. KEV CAPTURE RATES
# ============================================================

kev = df[df["cisa_kev"]]
non_kev = df[~df["cisa_kev"]]

kev_capture = kev["base_high_priority"].mean()
non_kev_capture = non_kev["base_high_priority"].mean()

print("\n" + "=" * 65)
print("HIGH-PRIORITY CAPTURE")
print("=" * 65)

print(
    f"KEV P1/P2:     "
    f"{kev['base_high_priority'].sum()}/{len(kev)} "
    f"({kev_capture * 100:.2f}%)"
)

print(
    f"Non-KEV P1/P2: "
    f"{non_kev['base_high_priority'].sum()}/{len(non_kev)} "
    f"({non_kev_capture * 100:.2f}%)"
)


# ============================================================
# 8. SPEARMAN CORRELATION: PRIORITY VS EPSS
# ============================================================

# Priority number increases as urgency decreases:
# P1 = 1 ... P4 = 4.
#
# Therefore a useful prioritisation model should normally produce
# a NEGATIVE correlation between priority number and EPSS.

rho, spearman_p = spearmanr(
    df["base_priority_number"],
    df["epss_score"]
)

print("\n" + "=" * 65)
print("SPEARMAN: BASE PRIORITY VS EPSS")
print("=" * 65)

print(f"Spearman rho: {rho:.4f}")
print(f"P-value:      {spearman_p:.10f}")

if spearman_p < 0.05:
    print(
        "Result: statistically significant relationship "
        "between framework priority and EPSS."
    )
else:
    print(
        "Result: relationship is not statistically significant "
        "at alpha = 0.05."
    )


# ============================================================
# 9. SAVE RESULTS
# ============================================================

summary = {
    "sample_size": int(len(df)),
    "kev_count": int(df["cisa_kev"].sum()),
    "non_kev_count": int((~df["cisa_kev"]).sum()),

    "kev_high_priority_count": int(
        kev["base_high_priority"].sum()
    ),

    "non_kev_high_priority_count": int(
        non_kev["base_high_priority"].sum()
    ),

    "kev_high_priority_rate": float(kev_capture),
    "non_kev_high_priority_rate": float(non_kev_capture),

    "fisher_odds_ratio": float(odds_ratio),
    "fisher_p_value": float(fisher_p),

    "spearman_rho_priority_epss": float(rho),
    "spearman_p_value": float(spearman_p),
}

SUMMARY_FILE = (
        OUTPUT_DIR
        / "external_validation_statistical_summary.json"
)

TABLE_FILE = (
        OUTPUT_DIR
        / "external_validation_statistical_data.csv"
)

with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=4)

df.to_csv(TABLE_FILE, index=False)


# ============================================================
# 10. FINISH
# ============================================================

print("\n" + "=" * 65)
print("STATISTICAL EXTERNAL VALIDATION COMPLETE")
print("=" * 65)

print("\nSaved:")
print(f"- {SUMMARY_FILE}")
print(f"- {TABLE_FILE}")