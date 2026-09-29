import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TEST_FILE = PROJECT_ROOT / "data" / "ml" / "ml_test_v2.csv"
MODEL_FILE = (
        PROJECT_ROOT
        / "data"
        / "ml"
        / "ml_results"
        / "random_forest_model_v2.joblib"
)

OUTPUT_FILE = (
        PROJECT_ROOT
        / "data"
        / "ml"
        / "ml_results"
        / "ml_xai_comparison_v2.json"
)

TARGET = "priority"

DROP_COLUMNS = [
    "event_id",
    "seed_event_id",
]

LABELS = ["P1", "P2", "P3", "P4"]


def priority_distance(actual: str, predicted: str) -> int:
    ordering = {
        "P1": 1,
        "P2": 2,
        "P3": 3,
        "P4": 4,
    }

    return abs(
        ordering[actual]
        - ordering[predicted]
    )


def main() -> None:

    test_df = pd.read_csv(TEST_FILE)

    model = joblib.load(MODEL_FILE)

    y_framework = test_df[TARGET]

    X_test = test_df.drop(
        columns=[TARGET] + DROP_COLUMNS,
        errors="ignore",
    )

    predictions = model.predict(X_test)

    probabilities = model.predict_proba(X_test)

    classes = model.named_steps[
        "classifier"
    ].classes_

    comparison_rows = []

    exact_matches = 0
    adjacent_errors = 0
    severe_errors = 0

    for index, predicted in enumerate(predictions):

        framework_priority = y_framework.iloc[index]

        probability_map = {
            priority: float(probability)
            for priority, probability in zip(
                classes,
                probabilities[index],
            )
        }

        confidence = max(
            probability_map.values()
        )

        distance = priority_distance(
            framework_priority,
            predicted,
        )

        if distance == 0:
            exact_matches += 1

        elif distance == 1:
            adjacent_errors += 1

        else:
            severe_errors += 1

        comparison_rows.append(
            {
                "event_id": test_df.iloc[index][
                    "event_id"
                ],
                "seed_event_id": test_df.iloc[index][
                    "seed_event_id"
                ],
                "framework_priority": framework_priority,
                "ml_priority": predicted,
                "match": framework_priority == predicted,
                "priority_distance": distance,
                "ml_confidence": confidence,
                "class_probabilities": probability_map,
            }
        )

    agreement = accuracy_score(
        y_framework,
        predictions,
    )

    matrix = confusion_matrix(
        y_framework,
        predictions,
        labels=LABELS,
    )

    results = {
        "test_events": len(test_df),
        "agreement_rate": float(agreement),
        "exact_matches": exact_matches,
        "adjacent_priority_errors": adjacent_errors,
        "severe_priority_errors": severe_errors,
        "labels": LABELS,
        "confusion_matrix": matrix.tolist(),
        "comparisons": comparison_rows,
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
            "w",
            encoding="utf-8",
    ) as file:

        json.dump(
            results,
            file,
            indent=2,
        )

    print("ML vs XAI comparison completed.")
    print(f"\nTest events: {len(test_df)}")

    print(
        f"Exact agreement: "
        f"{exact_matches}/{len(test_df)} "
        f"({agreement * 100:.2f}%)"
    )

    print(
        f"Adjacent priority errors: "
        f"{adjacent_errors}"
    )

    print(
        f"Severe priority errors: "
        f"{severe_errors}"
    )

    print("\nConfusion matrix:")
    print(f"Labels: {LABELS}")
    print(matrix)

    print("\nSaved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()