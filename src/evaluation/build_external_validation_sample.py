from pathlib import Path
import pandas as pd

# =========================================================
# 1. PATHS
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DIR = PROJECT_ROOT / "external_validation" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "external_validation" / "processed"

ENRICHED_FILE = RAW_DIR / "cve_cisa_epss_enriched_dataset.csv"
NVD_FILE = RAW_DIR / "nvd.csv"

OUTPUT_FILE = PROCESSED_DIR / "external_validation_sample_100.csv"


# =========================================================
# 2. SAMPLING CONFIGURATION
# =========================================================

START_YEAR = 2023
END_YEAR = 2025

N_KEV = 50
N_NON_KEV = 50

RANDOM_STATE = 42


# =========================================================
# 3. LOAD DATASETS
# =========================================================

print("=" * 70)
print("BUILDING EXTERNAL VALIDATION SAMPLE")
print("=" * 70)

print("\nLoading enriched CVE dataset...")

cve_df = pd.read_csv(
    ENRICHED_FILE,
    low_memory=False
)

print(f"Loaded {len(cve_df):,} CVE records.")
print("\nPublished date diagnostic:")
print(cve_df["published_date"].head(10).to_string())
print("\nPublished date dtype:")
print(cve_df["published_date"].dtype)

print("\nLoading NVD dataset...")

nvd_df = pd.read_csv(
    NVD_FILE,
    low_memory=False
)

print(f"Loaded {len(nvd_df):,} NVD records.")


# =========================================================
# 4. CHECK REQUIRED COLUMNS
# =========================================================

required_cve_columns = [
    "cve_id",
    "base_severity",
    "base_score",
    "exploitability_score",
    "impact_score",
    "epss_score",
    "epss_perc",
    "cisa_kev",
    "attack_vector",
    "published_date"
]

missing = [
    column
    for column in required_cve_columns
    if column not in cve_df.columns
]

if missing:
    raise ValueError(
        f"Missing required columns from enriched dataset: {missing}"
    )


required_nvd_columns = [
    "id",
    "description",
    "references",
    "configurations"
]

missing_nvd = [
    column
    for column in required_nvd_columns
    if column not in nvd_df.columns
]

if missing_nvd:
    raise ValueError(
        f"Missing required columns from NVD dataset: {missing_nvd}"
    )


# =========================================================
# 5. CLEAN PUBLICATION DATE
# =========================================================

print("\nOriginal published_date examples:")
print(cve_df["published_date"].head(10).to_string())

# Keep a copy of the original values
original_dates = cve_df["published_date"].copy()

# First try normal string/date parsing
parsed_dates = pd.to_datetime(
    original_dates,
    errors="coerce",
    utc=True,
    format="mixed"
)

# If any values failed, try numeric Unix timestamps
failed_mask = parsed_dates.isna()

if failed_mask.any():

    numeric_dates = pd.to_numeric(
        original_dates[failed_mask],
        errors="coerce"
    )

    # Try milliseconds first
    parsed_ms = pd.to_datetime(
        numeric_dates,
        unit="ms",
        errors="coerce",
        utc=True
    )

    parsed_dates.loc[failed_mask] = parsed_ms


cve_df["published_date"] = parsed_dates
cve_df["published_year"] = cve_df["published_date"].dt.year


print("\nParsed publication years:")
print(
    cve_df["published_year"]
    .value_counts(dropna=False)
    .sort_index()
    .tail(15)
)

print(
    "\nSuccessfully parsed dates:",
    cve_df["published_date"].notna().sum()
)

print(
    "Failed date conversions:",
    cve_df["published_date"].isna().sum()
)


# =========================================================
# 6. RESTRICT TO STUDY PERIOD
# =========================================================

filtered = cve_df[
    cve_df["published_year"].between(
        START_YEAR,
        END_YEAR,
        inclusive="both"
    )
].copy()

print(
    f"\nCVEs published between {START_YEAR} and {END_YEAR}: "
    f"{len(filtered):,}"
)


# =========================================================
# 7. NORMALISE CISA KEV FIELD
# =========================================================

def convert_kev(value):
    if pd.isna(value):
        return None

    text = str(value).strip().lower()

    if text in ["true", "1", "yes", "y"]:
        return True

    if text in ["false", "0", "no", "n"]:
        return False

    return None


filtered["cisa_kev"] = filtered["cisa_kev"].apply(convert_kev)

filtered = filtered.dropna(
    subset=["cisa_kev"]
)


# =========================================================
# 8. REMOVE RECORDS MISSING ESSENTIAL TECHNICAL DATA
# =========================================================

essential_columns = [
    "cve_id",
    "base_score",
    "epss_score",
    "attack_vector"
]

before_cleaning = len(filtered)

filtered = filtered.dropna(
    subset=essential_columns
)

print(
    f"Removed {before_cleaning - len(filtered):,} records "
    f"with missing essential values."
)


# =========================================================
# 9. REMOVE DUPLICATE CVE IDs
# =========================================================

before_duplicates = len(filtered)

filtered = filtered.drop_duplicates(
    subset=["cve_id"],
    keep="first"
)

print(
    f"Removed {before_duplicates - len(filtered):,} duplicate CVEs."
)


# =========================================================
# 10. SPLIT KEV / NON-KEV
# =========================================================

kev_df = filtered[
    filtered["cisa_kev"] == True
    ].copy()

non_kev_df = filtered[
    filtered["cisa_kev"] == False
    ].copy()

print("\nEligible records:")
print(f"KEV:     {len(kev_df):,}")
print(f"Non-KEV: {len(non_kev_df):,}")


if len(kev_df) < N_KEV:
    raise ValueError(
        f"Only {len(kev_df)} KEV CVEs available; "
        f"{N_KEV} requested."
    )

if len(non_kev_df) < N_NON_KEV:
    raise ValueError(
        f"Only {len(non_kev_df)} non-KEV CVEs available; "
        f"{N_NON_KEV} requested."
    )


# =========================================================
# 11. SAMPLE 50 KEV + 50 NON-KEV
# =========================================================

kev_sample = kev_df.sample(
    n=N_KEV,
    random_state=RANDOM_STATE
)

non_kev_sample = non_kev_df.sample(
    n=N_NON_KEV,
    random_state=RANDOM_STATE
)


sample = pd.concat(
    [
        kev_sample,
        non_kev_sample
    ],
    ignore_index=True
)


# Randomise row order reproducibly
sample = sample.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(drop=True)


# =========================================================
# 12. ENRICH WITH NVD TEXT FIELDS
# =========================================================

nvd_subset = nvd_df[
    [
        "id",
        "description",
        "references",
        "configurations"
    ]
].copy()

nvd_subset = nvd_subset.rename(
    columns={
        "id": "cve_id"
    }
)

# Protect against duplicate IDs in NVD
nvd_subset = nvd_subset.drop_duplicates(
    subset=["cve_id"],
    keep="first"
)

sample = sample.merge(
    nvd_subset,
    how="left",
    on="cve_id"
)


# =========================================================
# 13. ADD VALIDATION IDENTIFIER
# =========================================================

sample.insert(
    0,
    "validation_id",
    [
        f"EXT-{number:03d}"
        for number in range(1, len(sample) + 1)
    ]
)


# =========================================================
# 14. SAVE FROZEN SAMPLE
# =========================================================

PROCESSED_DIR.mkdir(
    parents=True,
    exist_ok=True
)

sample.to_csv(
    OUTPUT_FILE,
    index=False
)


# =========================================================
# 15. VALIDATION CHECKS
# =========================================================

print("\n" + "=" * 70)
print("VALIDATION CHECKS")
print("=" * 70)

print(f"\nTotal sampled CVEs: {len(sample)}")

print("\nKEV distribution:")
print(sample["cisa_kev"].value_counts())

print("\nPublication years:")
print(
    sample["published_year"]
    .value_counts()
    .sort_index()
)

print("\nSeverity distribution:")
print(
    sample["base_severity"]
    .value_counts(dropna=False)
)

print("\nCVSS summary:")
print(
    sample["base_score"].describe()
)

print("\nEPSS summary:")
print(
    sample["epss_score"].describe()
)

print(
    "\nDuplicate CVE IDs:",
    sample["cve_id"].duplicated().sum()
)

print(
    "Missing NVD descriptions:",
    sample["description"].isna().sum()
)


# =========================================================
# 16. FINAL MESSAGE
# =========================================================

print("\n" + "=" * 70)
print("EXTERNAL VALIDATION SAMPLE COMPLETE")
print("=" * 70)

print(f"\nSaved to:\n{OUTPUT_FILE}")

print(
    "\nDo not manually modify this file. "
    "This is the frozen external validation sample."
)