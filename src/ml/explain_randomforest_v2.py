import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TEST_FILE = (
        PROJECT_ROOT
        / "data"
        / "ml"
        / "ml_test_v2.csv"
)

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
        / "random_forest_shap_v2.json"
)

TARGET = "priority"

DROP_COLUMNS = [
    "event_id",
    "seed_event_id",
]

TOP_FEATURES = 10

# Explain a manageable subset first.
MAX_EXPLANATIONS = 100


def main() -> None:

    test_df = pd.read_csv(TEST_FILE)

    pipeline = joblib.load(MODEL_FILE)

    X_test = test_df.drop(
        columns=[TARGET] + DROP_COLUMNS,
        errors="ignore",
    )

    preprocessor = pipeline.named_steps[
        "preprocessor"
    ]

    classifier = pipeline.named_steps[
        "classifier"
    ]


    X_transformed = preprocessor.transform(X_test)

    if hasattr(X_transformed, "toarray"):
        X_transformed = X_transformed.toarray()

    feature_names = (
        preprocessor.get_feature_names_out()
    )

    classes = classifier.classes_

    print("Random Forest V2 SHAP Explanation")
    print("=================================")

    print(
        f"\nTest rows available: {len(X_test)}"
    )

    print(
        f"Transformed features: "
        f"{len(feature_names)}"
    )

    sample_size = min(
        MAX_EXPLANATIONS,
        len(X_test),
    )

    X_sample = X_transformed[:sample_size]

    raw_sample = test_df.iloc[:sample_size]

    print(
        f"Events being explained: "
        f"{sample_size}"
    )

    # TreeExplainer is appropriate for Random Forest.
    explainer = shap.TreeExplainer(
        classifier
    )

    shap_values = explainer.shap_values(
        X_sample
    )

    predictions = classifier.predict(
        X_sample
    )

    probabilities = classifier.predict_proba(
        X_sample
    )

    explanations = []

    for row_index in range(sample_size):

        predicted_class = predictions[
            row_index
        ]

        predicted_class_index = list(
            classes
        ).index(predicted_class)



        if isinstance(shap_values, list):

            row_shap = np.asarray(
                shap_values[
                    predicted_class_index
                ][row_index]
            )

        else:

            shap_array = np.asarray(
                shap_values
            )

            if shap_array.ndim == 3:

                row_shap = shap_array[
                    row_index,
                    :,
                    predicted_class_index,
                ]

            elif shap_array.ndim == 2:

                row_shap = shap_array[
                    row_index
                ]

            else:

                raise ValueError(
                    "Unexpected SHAP output shape: "
                    f"{shap_array.shape}"
                )

        feature_contributions = []

        for feature_name, contribution in zip(
                feature_names,
                row_shap,
        ):

            feature_contributions.append(
                {
                    "feature": str(
                        feature_name
                    ),
                    "shap_value": float(
                        contribution
                    ),
                    "absolute_shap_value": float(
                        abs(contribution)
                    ),
                }
            )

        feature_contributions.sort(
            key=lambda item: item[
                "absolute_shap_value"
            ],
            reverse=True,
        )

        top_features = (
            feature_contributions[
                :TOP_FEATURES
            ]
        )

        probability_map = {
            str(class_name): float(
                probability
            )
            for class_name, probability
            in zip(
                classes,
                probabilities[row_index],
            )
        }

        explanations.append(
            {
                "event_id": raw_sample.iloc[
                    row_index
                ].get(
                    "event_id",
                    "",
                ),

                "seed_event_id": raw_sample.iloc[
                    row_index
                ].get(
                    "seed_event_id",
                    "",
                ),

                "framework_priority": raw_sample.iloc[
                    row_index
                ][TARGET],

                "ml_priority": str(
                    predicted_class
                ),

                "agreement": (
                        raw_sample.iloc[
                            row_index
                        ][TARGET]
                        == predicted_class
                ),

                "ml_confidence": float(
                    max(
                        probabilities[
                            row_index
                        ]
                    )
                ),

                "class_probabilities": (
                    probability_map
                ),

                "top_shap_features": (
                    top_features
                ),
            }
        )

    results = {
        "model": "Random Forest V2",
        "test_rows": len(test_df),
        "explained_rows": sample_size,
        "transformed_feature_count": len(
            feature_names
        ),
        "classes": [
            str(value)
            for value in classes
        ],
        "explanations": explanations,
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

    print("\nSHAP explanations generated successfully.")

    print("\nFirst five explanations:")

    for explanation in explanations[:5]:

        print("\n--------------------------------")

        print(
            "Event:",
            explanation["event_id"],
        )

        print(
            "Framework priority:",
            explanation[
                "framework_priority"
            ],
        )

        print(
            "ML priority:",
            explanation[
                "ml_priority"
            ],
        )

        print(
            "Agreement:",
            explanation[
                "agreement"
            ],
        )

        print(
            "ML confidence:",
            f"{explanation['ml_confidence']:.4f}",
        )

        print("Top SHAP features:")

        for feature in explanation[
            "top_shap_features"
        ][:5]:

            print(
                f"  {feature['feature']}: "
                f"{feature['shap_value']:+.4f}"
            )

    print("\nSaved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()