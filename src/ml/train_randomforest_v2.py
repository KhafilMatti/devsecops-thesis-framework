import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TRAIN_FILE = (
        PROJECT_ROOT
        / "data"
        / "ml"
        / "ml_train_v2.csv"
)

TEST_FILE = (
        PROJECT_ROOT
        / "data"
        / "ml"
        / "ml_test_v2.csv"
)

RESULTS_DIR = (
        PROJECT_ROOT
        / "data"
        / "ml"
        / "ml_results"
)

MODEL_FILE = RESULTS_DIR / "random_forest_model_v2.joblib"
RESULTS_FILE = RESULTS_DIR / "random_forest_results_v2.json"

TARGET = "priority"

DROP_COLUMNS = [
    "event_id",
    "seed_event_id",
]

LABELS = [
    "P1",
    "P2",
    "P3",
    "P4",
]


def main() -> None:

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    train_df = pd.read_csv(TRAIN_FILE)
    test_df = pd.read_csv(TEST_FILE)

    print("Random Forest V2")
    print("================")

    print(f"\nTraining rows: {len(train_df)}")
    print(f"Testing rows: {len(test_df)}")

    y_train = train_df[TARGET]
    y_test = test_df[TARGET]

    X_train = train_df.drop(
        columns=[TARGET] + DROP_COLUMNS,
        errors="ignore",
    )

    X_test = test_df.drop(
        columns=[TARGET] + DROP_COLUMNS,
        errors="ignore",
    )

    print(
        f"Features available to model: "
        f"{len(X_train.columns)}"
    )

    categorical_features = (
        X_train
        .select_dtypes(
            include=["object", "category", "bool"]
        )
        .columns
        .tolist()
    )

    numerical_features = [
        column
        for column in X_train.columns
        if column not in categorical_features
    ]

    print(
        f"Categorical features: "
        f"{len(categorical_features)}"
    )

    print(
        f"Numerical features: "
        f"{len(numerical_features)}"
    )

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore",
                ),
                categorical_features,
            ),
            (
                "numerical",
                "passthrough",
                numerical_features,
            ),
        ]
    )

    # Keep parameters fixed for a fair V2 comparison.
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", model),
        ]
    )

    print("\nTraining model...")

    pipeline.fit(
        X_train,
        y_train,
    )

    predictions = pipeline.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    precision, recall, f1, _ = (
        precision_recall_fscore_support(
            y_test,
            predictions,
            labels=LABELS,
            average="macro",
            zero_division=0,
        )
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=LABELS,
    )

    report = classification_report(
        y_test,
        predictions,
        labels=LABELS,
        output_dict=True,
        zero_division=0,
    )

    # -------------------------------------------------------------
    # Feature importance
    # -------------------------------------------------------------

    preprocessor_fitted = (
        pipeline.named_steps["preprocessor"]
    )

    classifier_fitted = (
        pipeline.named_steps["classifier"]
    )

    feature_names = (
        preprocessor_fitted.get_feature_names_out()
    )

    feature_importances = (
        classifier_fitted.feature_importances_
    )

    importance_pairs = sorted(
        zip(
            feature_names,
            feature_importances,
        ),
        key=lambda item: item[1],
        reverse=True,
    )

    print("\nTop feature importances:")
    print("========================")

    for feature, importance in importance_pairs[:20]:
        print(
            f"{feature:<55} "
            f"{importance:.4f}"
        )

    print("\nPerformance:")
    print(f"Accuracy:        {accuracy:.4f}")
    print(f"Macro precision: {precision:.4f}")
    print(f"Macro recall:    {recall:.4f}")
    print(f"Macro F1:        {f1:.4f}")

    print("\nConfusion matrix:")
    print(f"Labels: {LABELS}")
    print(matrix)

    print("\nClassification report:")

    print(
        classification_report(
            y_test,
            predictions,
            labels=LABELS,
            zero_division=0,
        )
    )

    results = {
        "model": "Random Forest V2",
        "training_rows": len(train_df),
        "testing_rows": len(test_df),
        "features": X_train.columns.tolist(),
        "accuracy": float(accuracy),
        "macro_precision": float(precision),
        "macro_recall": float(recall),
        "macro_f1": float(f1),
        "labels": LABELS,
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
        "top_feature_importances": [
            {
                "feature": feature,
                "importance": float(importance),
            }
            for feature, importance in importance_pairs[:20]
        ],
    }

    joblib.dump(
        pipeline,
        MODEL_FILE,
    )

    with RESULTS_FILE.open(
            "w",
            encoding="utf-8",
    ) as file:
        json.dump(
            results,
            file,
            indent=4,
        )

    print("\nModel saved to:")
    print(MODEL_FILE)

    print("\nResults saved to:")
    print(RESULTS_FILE)


if __name__ == "__main__":
    main()