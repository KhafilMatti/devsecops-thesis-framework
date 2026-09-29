# compare_prioritisation_models.py

import os
import pandas as pd
from pathlib import Path
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


# ============================================================
# 1. CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_FILE = PROJECT_ROOT / "data" / "ml" / "ml_train_v2.csv"
TARGET = "priority"

TEST_SIZE = 0.20
RANDOM_STATE = 42

# Random Forest settings kept identical for every experiment.
# This is important because we want the feature sets, rather
# than different model configurations, to explain differences
# in performance.
RF_PARAMS = {
    "n_estimators": 300,
    "random_state": RANDOM_STATE,
    "class_weight": "balanced",
    "n_jobs": -1
}


# ============================================================
# 2. LOAD DATASET
# ============================================================

if not os.path.exists(DATA_FILE):
    raise FileNotFoundError(
        f"Could not find '{DATA_FILE}'. "
        f"Place this script in the same folder as ml_train_v2.csv "
        f"or change DATA_FILE to the correct path."
    )

df = pd.read_csv(DATA_FILE)

print("=" * 70)
print("PRIORITISATION MODEL COMPARISON")
print("=" * 70)

print(f"\nDataset loaded: {DATA_FILE}")
print(f"Rows: {df.shape[0]}")
print(f"Columns: {df.shape[1]}")

print("\nPriority distribution:")
print(df[TARGET].value_counts().sort_index())


# ============================================================
# 3. DEFINE FEATURE GROUPS
# ============================================================

# ------------------------------------------------------------
# Model 1: Severity-only baseline
# ------------------------------------------------------------
# This represents a conventional prioritisation approach where
# technical severity is the main information used.
severity_features = [
    "cvss_score",
    "severity"
]


# ------------------------------------------------------------
# Model 2: Context-aware model
# ------------------------------------------------------------
# Deliberately excludes CVSS score and severity.
# This lets us test how well organisational, operational,
# runtime and threat-context information performs by itself.
context_features = [
    "event_type",
    "source_platform",
    "package_ecosystem",
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
    "stride_spoofing",
    "stride_tampering",
    "stride_repudiation",
    "stride_information_disclosure",
    "stride_denial_of_service",
    "stride_elevation_of_privilege",
    "patch_available"
]


# ------------------------------------------------------------
# Model 3: Combined model
# ------------------------------------------------------------
# Uses both traditional severity information and contextual
# information.
combined_features = severity_features + context_features


# ============================================================
# 4. VALIDATE REQUIRED COLUMNS
# ============================================================

required_columns = set(
    severity_features +
    context_features +
    [TARGET]
)

missing_columns = required_columns.difference(df.columns)

if missing_columns:
    raise ValueError(
        "The following required columns are missing from the dataset:\n"
        + "\n".join(sorted(missing_columns))
    )


# ============================================================
# 5. CREATE ONE COMMON TRAIN / TEST SPLIT
# ============================================================

# We split the row indices once and reuse them for every model.
# This guarantees that all approaches are evaluated on exactly
# the same training and testing observations.

train_idx, test_idx = train_test_split(
    df.index,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=df[TARGET]
)

y_train = df.loc[train_idx, TARGET]
y_test = df.loc[test_idx, TARGET]

print("\nTrain/test split:")
print(f"Training rows: {len(train_idx)}")
print(f"Testing rows:  {len(test_idx)}")

print("\nTest-set priority distribution:")
print(y_test.value_counts().sort_index())


# ============================================================
# 6. FUNCTION TO BUILD PREPROCESSING + RANDOM FOREST PIPELINE
# ============================================================

def build_pipeline(dataframe, feature_list):
    """
    Creates a preprocessing pipeline based on the supplied
    feature list.

    Numeric columns are passed directly to Random Forest.
    Categorical columns are one-hot encoded.
    """

    X = dataframe[feature_list]

    numeric_features = X.select_dtypes(
        include=["number", "bool"]
    ).columns.tolist()

    categorical_features = X.select_dtypes(
        exclude=["number", "bool"]
    ).columns.tolist()

    transformers = []

    if numeric_features:
        transformers.append(
            (
                "numeric",
                "passthrough",
                numeric_features
            )
        )

    if categorical_features:
        transformers.append(
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=False
                ),
                categorical_features
            )
        )

    preprocessor = ColumnTransformer(
        transformers=transformers,
        remainder="drop"
    )

    classifier = RandomForestClassifier(**RF_PARAMS)

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", classifier)
        ]
    )

    return pipeline, numeric_features, categorical_features


# ============================================================
# 7. MODEL EVALUATION FUNCTION
# ============================================================

def evaluate_model(model_name, feature_list):
    """
    Trains and evaluates one prioritisation model.
    """

    print("\n" + "=" * 70)
    print(model_name.upper())
    print("=" * 70)

    print(f"\nNumber of original features: {len(feature_list)}")
    print("Features:")
    for feature in feature_list:
        print(f"  - {feature}")

    X_train = df.loc[train_idx, feature_list]
    X_test = df.loc[test_idx, feature_list]

    pipeline, numeric_features, categorical_features = build_pipeline(
        df,
        feature_list
    )

    print("\nNumeric features:")
    print(numeric_features)

    print("\nCategorical features:")
    print(categorical_features)

    # Train
    pipeline.fit(X_train, y_train)

    # Predict
    y_pred = pipeline.predict(X_test)

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)

    macro_precision = precision_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    macro_recall = recall_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    macro_f1 = f1_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    weighted_f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    print("\nPerformance:")
    print(f"Accuracy:        {accuracy:.4f}")
    print(f"Macro Precision: {macro_precision:.4f}")
    print(f"Macro Recall:    {macro_recall:.4f}")
    print(f"Macro F1:        {macro_f1:.4f}")
    print(f"Weighted F1:     {weighted_f1:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            digits=4,
            zero_division=0
        )
    )

    labels = sorted(df[TARGET].unique())

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels
    )

    cm_df = pd.DataFrame(
        cm,
        index=[f"Actual_{label}" for label in labels],
        columns=[f"Predicted_{label}" for label in labels]
    )

    print("\nConfusion Matrix:")
    print(cm_df)

    # Save individual confusion matrix
    safe_name = (
        model_name.lower()
        .replace(" ", "_")
        .replace("-", "_")
    )

    cm_filename = f"{safe_name}_confusion_matrix.csv"
    cm_df.to_csv(cm_filename)

    print(f"\nSaved confusion matrix: {cm_filename}")

    return {
        "Model": model_name,
        "Original Features": len(feature_list),
        "Accuracy": accuracy,
        "Macro Precision": macro_precision,
        "Macro Recall": macro_recall,
        "Macro F1": macro_f1,
        "Weighted F1": weighted_f1
    }


# ============================================================
# 8. RUN ALL THREE EXPERIMENTS
# ============================================================

results = []

results.append(
    evaluate_model(
        "Severity-only",
        severity_features
    )
)

results.append(
    evaluate_model(
        "Context-aware",
        context_features
    )
)

results.append(
    evaluate_model(
        "Combined",
        combined_features
    )
)


# ============================================================
# 9. CREATE COMPARISON TABLE
# ============================================================

results_df = pd.DataFrame(results)

results_df = results_df[
    [
        "Model",
        "Original Features",
        "Accuracy",
        "Macro Precision",
        "Macro Recall",
        "Macro F1",
        "Weighted F1"
    ]
]

print("\n" + "=" * 70)
print("FINAL MODEL COMPARISON")
print("=" * 70)

print(
    results_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)


# ============================================================
# 10. CALCULATE IMPROVEMENTS OVER SEVERITY BASELINE
# ============================================================

severity_row = results_df[
    results_df["Model"] == "Severity-only"
    ].iloc[0]

comparison_rows = []

for _, row in results_df.iterrows():

    accuracy_change = (
            row["Accuracy"] - severity_row["Accuracy"]
    )

    macro_f1_change = (
            row["Macro F1"] - severity_row["Macro F1"]
    )

    comparison_rows.append(
        {
            "Model": row["Model"],
            "Accuracy Difference vs Severity": accuracy_change,
            "Macro F1 Difference vs Severity": macro_f1_change
        }
    )

improvement_df = pd.DataFrame(comparison_rows)

print("\n" + "=" * 70)
print("CHANGE RELATIVE TO SEVERITY-ONLY BASELINE")
print("=" * 70)

print(
    improvement_df.to_string(
        index=False,
        float_format=lambda x: f"{x:+.4f}"
    )
)


# ============================================================
# 11. SAVE RESULTS
# ============================================================

results_filename = "prioritisation_model_comparison.csv"
improvement_filename = "prioritisation_model_improvements.csv"

results_df.to_csv(
    results_filename,
    index=False
)

improvement_df.to_csv(
    improvement_filename,
    index=False
)

print("\nSaved files:")
print(f"  - {results_filename}")
print(f"  - {improvement_filename}")

print("\nExperiment complete.")