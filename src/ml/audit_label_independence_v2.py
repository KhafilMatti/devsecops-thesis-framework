from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TRAIN_FILE = PROJECT_ROOT / "data" / "ml" / "ml_train_v2.csv"
TEST_FILE = PROJECT_ROOT / "data" / "ml" / "ml_test_v2.csv"

TARGET = "priority"

IDENTIFIER_COLUMNS = [
    "event_id",
    "seed_event_id",
]

TECHNICAL_FEATURES = [
    "cvss_score",
    "severity",
]

CONTEXT_FEATURES = [
    "environment",
    "internet_facing",
    "runtime_reachable",
    "business_criticality",
    "deployment_stage",
    "data_sensitivity",
    "safety_impact",
    "operational_disruption",
    "financial_loss",
    "regulatory_exposure",
    "reputational_damage",
]

STRIDE_FEATURES = [
    "stride_spoofing",
    "stride_tampering",
    "stride_repudiation",
    "stride_information_disclosure",
    "stride_denial_of_service",
    "stride_elevation_of_privilege",
]

OTHER_FEATURES = [
    "patch_available",
]


def section(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def show_priority_distribution(
        df: pd.DataFrame,
        name: str,
) -> None:

    section(f"{name} PRIORITY DISTRIBUTION")

    counts = df[TARGET].value_counts().sort_index()
    percentages = (
            df[TARGET]
            .value_counts(normalize=True)
            .sort_index()
            * 100
    )

    result = pd.DataFrame(
        {
            "count": counts,
            "percentage": percentages,
        }
    )

    print(result.round(2))


def inspect_identifier_leakage(
        train_df: pd.DataFrame,
        test_df: pd.DataFrame,
) -> None:

    section("IDENTIFIER / SEED AUDIT")

    for column in IDENTIFIER_COLUMNS:

        if column not in train_df.columns:
            print(f"{column}: not present")
            continue

        train_values = set(train_df[column].dropna())
        test_values = set(test_df[column].dropna())

        overlap = train_values.intersection(test_values)

        print(f"\n{column}")
        print(f"Training unique values: {len(train_values)}")
        print(f"Testing unique values:  {len(test_values)}")
        print(f"Overlap:                {len(overlap)}")

        if overlap:
            print("WARNING: overlap detected.")
        else:
            print("PASS: no train/test overlap.")


def inspect_feature_groups(df: pd.DataFrame) -> None:

    section("FEATURE GROUP AUDIT")

    groups = {
        "Technical": TECHNICAL_FEATURES,
        "Context": CONTEXT_FEATURES,
        "STRIDE": STRIDE_FEATURES,
        "Other": OTHER_FEATURES,
    }

    for name, features in groups.items():

        available = [
            feature
            for feature in features
            if feature in df.columns
        ]

        missing = sorted(set(features) - set(available))

        print(f"\n{name}")
        print(f"Available ({len(available)}):")

        for feature in available:
            print(f"  - {feature}")

        if missing:
            print("Missing:")
            for feature in missing:
                print(f"  - {feature}")


def inspect_single_feature_predictiveness(
        train_df: pd.DataFrame,
        test_df: pd.DataFrame,
) -> None:

    section("SINGLE-FEATURE PRIORITY PREDICTIVENESS")

    candidate_features = (
            TECHNICAL_FEATURES
            + CONTEXT_FEATURES
            + STRIDE_FEATURES
            + OTHER_FEATURES
    )

    results = []

    for feature in candidate_features:

        if feature not in train_df.columns:
            continue

        # For every feature value in the training set,
        # find the most common priority.
        mapping = (
            train_df.groupby(feature)[TARGET]
            .agg(lambda x: x.mode().iloc[0])
            .to_dict()
        )

        default_priority = train_df[TARGET].mode().iloc[0]

        predictions = (
            test_df[feature]
            .map(mapping)
            .fillna(default_priority)
        )

        accuracy = accuracy_score(
            test_df[TARGET],
            predictions,
        )

        results.append(
            {
                "feature": feature,
                "accuracy": accuracy,
            }
        )

    result_df = pd.DataFrame(results)

    result_df = result_df.sort_values(
        "accuracy",
        ascending=False,
    )

    print(
        result_df.to_string(
            index=False,
            formatters={
                "accuracy": "{:.4f}".format,
            },
        )
    )


def inspect_feature_target_relationships(
        df: pd.DataFrame,
) -> None:

    section("KEY FEATURE → PRIORITY RELATIONSHIPS")

    important_features = [
        "severity",
        "business_criticality",
        "data_sensitivity",
        "internet_facing",
        "runtime_reachable",
        "deployment_stage",
    ]

    for feature in important_features:

        if feature not in df.columns:
            continue

        print(f"\n--- {feature.upper()} ---")

        table = pd.crosstab(
            df[feature],
            df[TARGET],
            normalize="index",
        )

        print(table.round(3))


def inspect_exact_pattern_determinism(
        train_df: pd.DataFrame,
        test_df: pd.DataFrame,
) -> None:

    section("EXACT FEATURE-PATTERN AUDIT")

    excluded = {
        TARGET,
        "event_id",
        "seed_event_id",
    }

    features = [
        column
        for column in train_df.columns
        if column not in excluded
    ]

    grouped = (
        train_df
        .groupby(features, dropna=False)[TARGET]
        .agg(
            observations="size",
            unique_priorities="nunique",
        )
        .reset_index()
    )

    deterministic = grouped[
        grouped["unique_priorities"] == 1
        ]

    print(f"Feature columns checked: {len(features)}")
    print(f"Unique training patterns: {len(grouped)}")
    print(
        "Patterns associated with exactly one priority: "
        f"{len(deterministic)}"
    )

    if len(grouped) > 0:

        percentage = (
                len(deterministic)
                / len(grouped)
                * 100
        )

        print(
            "Deterministic pattern percentage: "
            f"{percentage:.2f}%"
        )


def main() -> None:

    train_df = pd.read_csv(TRAIN_FILE)
    test_df = pd.read_csv(TEST_FILE)

    section("ML LABEL-INDEPENDENCE AUDIT V2")

    print(f"Training rows: {len(train_df)}")
    print(f"Testing rows:  {len(test_df)}")
    print(f"Training columns: {len(train_df.columns)}")
    print(f"Testing columns:  {len(test_df.columns)}")

    show_priority_distribution(
        train_df,
        "TRAINING",
    )

    show_priority_distribution(
        test_df,
        "TESTING",
    )

    inspect_identifier_leakage(
        train_df,
        test_df,
    )

    inspect_feature_groups(train_df)

    inspect_single_feature_predictiveness(
        train_df,
        test_df,
    )

    inspect_feature_target_relationships(train_df)

    inspect_exact_pattern_determinism(
        train_df,
        test_df,
    )


if __name__ == "__main__":
    main()