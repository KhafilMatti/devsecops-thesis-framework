import csv
from pathlib import Path
from typing import Any

from sklearn.model_selection import GroupShuffleSplit


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
        PROJECT_ROOT
        / "data"
        / "ml"
        / "ml_training_features.csv"
)

OUTPUT_DIR = PROJECT_ROOT / "data" / "ml"

TRAIN_FILE = OUTPUT_DIR / "ml_train.csv"
TEST_FILE = OUTPUT_DIR / "ml_test.csv"

TEST_SIZE = 0.22
START_RANDOM_STATE = 42

EXPECTED_PRIORITIES = {"P1", "P2", "P3", "P4"}


def load_csv(path: Path) -> list[dict[str, Any]]:
    with path.open(
            "r",
            encoding="utf-8",
            newline="",
    ) as file:
        return list(csv.DictReader(file))


def save_csv(
        rows: list[dict[str, Any]],
        path: Path,
) -> None:
    if not rows:
        raise ValueError(
            f"Cannot save empty dataset to {path}"
        )

    with path.open(
            "w",
            encoding="utf-8",
            newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(rows[0].keys()),
        )

        writer.writeheader()
        writer.writerows(rows)


def priority_distribution(
        rows: list[dict[str, Any]],
) -> dict[str, int]:
    distribution: dict[str, int] = {}

    for row in rows:
        priority = row["priority"]

        distribution[priority] = (
                distribution.get(priority, 0) + 1
        )

    return distribution


def seed_ids(
        rows: list[dict[str, Any]],
) -> set[str]:
    return {
        row["seed_event_id"]
        for row in rows
    }


def contains_all_priorities(
        rows: list[dict[str, Any]],
) -> bool:
    priorities = {
        row["priority"]
        for row in rows
    }

    return EXPECTED_PRIORITIES.issubset(
        priorities
    )


def create_group_split(
        rows: list[dict[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    int,
]:
    groups = [
        row["seed_event_id"]
        for row in rows
    ]

    # Try deterministic random states until we find
    # a group split containing P1–P4 in both sets.
    for random_state in range(
            START_RANDOM_STATE,
            1000,
    ):
        splitter = GroupShuffleSplit(
            n_splits=1,
            test_size=TEST_SIZE,
            random_state=random_state,
        )

        train_indices, test_indices = next(
            splitter.split(
                X=rows,
                groups=groups,
            )
        )

        train_rows = [
            rows[index]
            for index in train_indices
        ]

        test_rows = [
            rows[index]
            for index in test_indices
        ]

        if (
                contains_all_priorities(train_rows)
                and contains_all_priorities(test_rows)
        ):
            return (
                train_rows,
                test_rows,
                random_state,
            )

    raise RuntimeError(
        "Could not create a group-aware split "
        "containing P1-P4 in both train and test sets."
    )


def main() -> None:
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {INPUT_FILE}"
        )

    rows = load_csv(INPUT_FILE)

    if not rows:
        raise ValueError(
            "ML feature dataset is empty."
        )

    train_rows, test_rows, random_state = (
        create_group_split(rows)
    )

    train_seeds = seed_ids(train_rows)
    test_seeds = seed_ids(test_rows)

    overlap = train_seeds.intersection(
        test_seeds
    )

    if overlap:
        raise RuntimeError(
            "Data leakage detected. "
            f"Seed IDs appear in both sets: {overlap}"
        )

    save_csv(
        train_rows,
        TRAIN_FILE,
    )

    save_csv(
        test_rows,
        TEST_FILE,
    )

    print(
        "Group-aware ML split created successfully."
    )

    print(f"\nRandom state: {random_state}")

    print(f"\nTotal rows: {len(rows)}")
    print(f"Training rows: {len(train_rows)}")
    print(f"Testing rows: {len(test_rows)}")

    print(
        f"\nTraining seed events: "
        f"{len(train_seeds)}"
    )

    print(
        f"Testing seed events: "
        f"{len(test_seeds)}"
    )

    print(
        f"Seed overlap: {len(overlap)}"
    )

    print("\nTraining priority distribution:")

    for priority, count in sorted(
            priority_distribution(
                train_rows
            ).items()
    ):
        print(f"  {priority}: {count}")

    print("\nTesting priority distribution:")

    for priority, count in sorted(
            priority_distribution(
                test_rows
            ).items()
    ):
        print(f"  {priority}: {count}")

    print("\nTraining seeds:")

    for seed in sorted(train_seeds):
        print(f"  - {seed}")

    print("\nTesting seeds:")

    for seed in sorted(test_seeds):
        print(f"  - {seed}")

    print(f"\nSaved training set to:")
    print(TRAIN_FILE)

    print("\nSaved testing set to:")
    print(TEST_FILE)


if __name__ == "__main__":
    main()