from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TRAIN_FILE = PROJECT_ROOT / "data" / "ml" / "ml_train_v2.csv"
TEST_FILE = PROJECT_ROOT / "data" / "ml" / "ml_test_v2.csv"

TARGET = "priority"


# ---------------------------------------------------------
# Feature groups
# ---------------------------------------------------------

SEVERITY_FEATURES = [
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
    "context_assignment_confidence",
    "stride_spoofing",
    "stride_tampering",
    "stride_repudiation",
    "stride_information_disclosure",
    "stride_denial_of_service",
    "stride_elevation_of_privilege",
    "patch_available",
]


def build_model(X_train: pd.DataFrame) -> Pipeline:

    categorical_features = [
        column
        for column in X_train.columns
        if X_train[column].dtype == "object"
    ]

    numerical_features = [
        column
        for column in X_train.columns
        if column not in categorical_features
    ]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                categorical_features,
            ),
            (
                "numerical",
                "passthrough",
                numerical_features,
            ),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1,
    )

    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", model),
        ]
    )


def evaluate_configuration(
        name: str,
        features: list[str],
        train_df: pd.DataFrame,
        test_df: pd.DataFrame,
) -> dict:

    # Ensure we only use features that actually exist.
    available_features = [
        feature for feature in features
        if feature in train_df.columns
    ]

    missing_features = sorted(set(features) - set(available_features))

    if missing_features:
        print(
            f"\nWarning: {name} missing features: "
            f"{missing_features}"
        )

    X_train = train_df[available_features]
    y_train = train_df[TARGET]

    X_test = test_df[available_features]
    y_test = test_df[TARGET]

    model = build_model(X_train)

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    results = {
        "Model": name,
        "Features": len(available_features),
        "Accuracy": accuracy_score(y_test, predictions),
        "Macro Precision": precision_score(
            y_test,
            predictions,
            average="macro",
            zero_division=0,
        ),
        "Macro Recall": recall_score(
            y_test,
            predictions,
            average="macro",
            zero_division=0,
        ),
        "Macro F1": f1_score(
            y_test,
            predictions,
            average="macro",
            zero_division=0,
        ),
    }

    return results


def main() -> None:

    train_df = pd.read_csv(TRAIN_FILE)
    test_df = pd.read_csv(TEST_FILE)

    print("ML Feature Ablation Experiment V2")
    print("================================")

    print(f"\nTraining rows: {len(train_df)}")
    print(f"Testing rows: {len(test_df)}")

    combined_features = SEVERITY_FEATURES + CONTEXT_FEATURES

    configurations = {
        "Severity-only": SEVERITY_FEATURES,
        "Context-only": CONTEXT_FEATURES,
        "Combined": combined_features,
    }

    results = []

    for name, features in configurations.items():

        print(f"\nTraining {name} model...")

        result = evaluate_configuration(
            name,
            features,
            train_df,
            test_df,
        )

        results.append(result)

    results_df = pd.DataFrame(results)

    print("\n")
    print("Ablation Results")
    print("================")

    print(
        results_df.to_string(
            index=False,
            formatters={
                "Accuracy": "{:.4f}".format,
                "Macro Precision": "{:.4f}".format,
                "Macro Recall": "{:.4f}".format,
                "Macro F1": "{:.4f}".format,
            },
        )
    )


if __name__ == "__main__":
    main()