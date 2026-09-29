import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TRAIN_FILE = PROJECT_ROOT / "data" / "ml" / "ml_train.csv"
TEST_FILE = PROJECT_ROOT / "data" / "ml" / "ml_test.csv"

OUTPUT_DIR = PROJECT_ROOT / "data" / "ml" / "ml_results"
MODEL_FILE = OUTPUT_DIR / "decision_tree_model.joblib"
RESULTS_FILE = OUTPUT_DIR / "decision_tree_results.json"

TARGET_COLUMN = "priority"

IDENTIFIER_COLUMNS = [
    "event_id",
    "seed_event_id",
]

RANDOM_STATE = 42


def main() -> None:
    if not TRAIN_FILE.exists():
        raise FileNotFoundError(
            f"Training file not found: {TRAIN_FILE}"
        )

    if not TEST_FILE.exists():
        raise FileNotFoundError(
            f"Testing file not found: {TEST_FILE}"
        )

    train_df = pd.read_csv(TRAIN_FILE)
    test_df = pd.read_csv(TEST_FILE)

    # Separate target from features.
    y_train = train_df[TARGET_COLUMN]
    y_test = test_df[TARGET_COLUMN]

    X_train = train_df.drop(
        columns=[TARGET_COLUMN] + IDENTIFIER_COLUMNS
    )

    X_test = test_df.drop(
        columns=[TARGET_COLUMN] + IDENTIFIER_COLUMNS
    )

    # Detect feature types automatically.
    categorical_columns = X_train.select_dtypes(
        include=["object"]
    ).columns.tolist()

    numeric_columns = [
        column
        for column in X_train.columns
        if column not in categorical_columns
    ]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore"
                ),
                categorical_columns,
            ),
            (
                "numeric",
                "passthrough",
                numeric_columns,
            ),
        ]
    )

    model = DecisionTreeClassifier(
        random_state=RANDOM_STATE,
        max_depth=8,
        min_samples_leaf=10,
        class_weight="balanced",
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", model),
        ]
    )

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

    precision_macro = precision_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    )

    recall_macro = recall_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    )

    f1_macro = f1_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0,
    )

    labels = ["P1", "P2", "P3", "P4"]

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=labels,
    )

    report = classification_report(
        y_test,
        predictions,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )

    results = {
        "model": "DecisionTreeClassifier",
        "random_state": RANDOM_STATE,
        "training_rows": len(train_df),
        "testing_rows": len(test_df),
        "accuracy": accuracy,
        "macro_precision": precision_macro,
        "macro_recall": recall_macro,
        "macro_f1": f1_macro,
        "labels": labels,
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
        "model_parameters": {
            "max_depth": 8,
            "min_samples_leaf": 10,
            "class_weight": "balanced",
        },
    }

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

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
            indent=2,
        )

    print(
        "Decision Tree training completed successfully."
    )

    print(
        f"\nTraining rows: {len(train_df)}"
    )

    print(
        f"Testing rows: {len(test_df)}"
    )

    print("\nPerformance:")
    print(f"  Accuracy:        {accuracy:.4f}")
    print(f"  Macro precision: {precision_macro:.4f}")
    print(f"  Macro recall:    {recall_macro:.4f}")
    print(f"  Macro F1:        {f1_macro:.4f}")

    print("\nConfusion matrix:")
    print("Labels:", labels)
    print(matrix)

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=labels,
            zero_division=0,
        )
    )

    print(f"Model saved to:")
    print(MODEL_FILE)

    print("\nResults saved to:")
    print(RESULTS_FILE)


if __name__ == "__main__":
    main()