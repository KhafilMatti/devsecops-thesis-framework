import copy
import csv
import json
import statistics
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

# Allow this script to import modules from src/analysis when it is executed
# from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_DIR = PROJECT_ROOT / "src" / "analysis"

if str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))

from riskenrichment import enrich_event  # noqa: E402


INPUT_FILE = Path("data/all_normalised_events.json")
CONTEXT_FILE = Path("data/asset_context.json")

JSON_OUTPUT_FILE = Path("data/scalability_metrics.json")
CSV_OUTPUT_FILE = Path("data/scalability_metrics.csv")

# The current dataset contains 18 events, so these multipliers produce:
# 18, 180, 900, 1,800 and 9,000 events.
WORKLOAD_MULTIPLIERS = [1, 10, 50, 100, 500]

# Run each workload several times to reduce the effect of random variation.
REPETITIONS = 5
WARMUP_RUNS = 1


def load_json(path: Path) -> Any:
    """Load a required JSON file."""
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def build_synthetic_dataset(
        base_events: list[dict[str, Any]],
        multiplier: int,
) -> list[dict[str, Any]]:
    """
    Duplicate the original normalised events while assigning unique event IDs.

    The event content and contextual characteristics are preserved so that
    every workload exercises the same enrichment and scoring logic.
    """
    synthetic_events: list[dict[str, Any]] = []

    for copy_number in range(multiplier):
        for original_event in base_events:
            event = copy.deepcopy(original_event)

            original_id = str(
                original_event.get("event_id")
                or "unknown-event"
            )

            event["event_id"] = (
                f"{original_id}-scale-{copy_number + 1}"
            )

            synthetic_events.append(event)

    return synthetic_events


def process_events(
        events: list[dict[str, Any]],
        context_profiles: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run the framework enrichment logic for every event."""
    enriched_events = [
        enrich_event(event, context_profiles)
        for event in events
    ]

    enriched_events.sort(
        key=lambda event: event.get("risk_score", 0),
        reverse=True,
    )

    return enriched_events


def run_once(
        events: list[dict[str, Any]],
        context_profiles: dict[str, Any],
) -> dict[str, float]:
    """Measure one complete enrichment run."""
    tracemalloc.start()

    start_time = time.perf_counter()

    processed_events = process_events(
        events=events,
        context_profiles=context_profiles,
    )

    elapsed_seconds = time.perf_counter() - start_time

    current_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(processed_events) != len(events):
        raise RuntimeError(
            "The number of processed events does not match the input."
        )

    throughput = (
        len(events) / elapsed_seconds
        if elapsed_seconds > 0
        else 0.0
    )

    return {
        "elapsed_seconds": elapsed_seconds,
        "throughput_events_per_second": throughput,
        "peak_memory_mb": peak_memory / (1024 * 1024),
        "ending_memory_mb": current_memory / (1024 * 1024),
    }


def summarise_runs(
        event_count: int,
        multiplier: int,
        runs: list[dict[str, float]],
) -> dict[str, Any]:
    """Calculate stable summary statistics from repeated measurements."""
    elapsed_values = [
        run["elapsed_seconds"]
        for run in runs
    ]

    throughput_values = [
        run["throughput_events_per_second"]
        for run in runs
    ]

    peak_memory_values = [
        run["peak_memory_mb"]
        for run in runs
    ]

    return {
        "multiplier": multiplier,
        "event_count": event_count,
        "repetitions": len(runs),

        "mean_elapsed_seconds": round(
            statistics.mean(elapsed_values),
            6,
        ),
        "median_elapsed_seconds": round(
            statistics.median(elapsed_values),
            6,
        ),
        "minimum_elapsed_seconds": round(
            min(elapsed_values),
            6,
        ),
        "maximum_elapsed_seconds": round(
            max(elapsed_values),
            6,
        ),
        "elapsed_standard_deviation": round(
            statistics.stdev(elapsed_values)
            if len(elapsed_values) > 1
            else 0.0,
            6,
        ),

        "mean_throughput_events_per_second": round(
            statistics.mean(throughput_values),
            2,
        ),
        "median_throughput_events_per_second": round(
            statistics.median(throughput_values),
            2,
        ),

        "mean_peak_memory_mb": round(
            statistics.mean(peak_memory_values),
            3,
        ),
        "maximum_peak_memory_mb": round(
            max(peak_memory_values),
            3,
        ),

        "individual_runs": [
            {
                "run_number": index,
                "elapsed_seconds": round(
                    run["elapsed_seconds"],
                    6,
                ),
                "throughput_events_per_second": round(
                    run["throughput_events_per_second"],
                    2,
                ),
                "peak_memory_mb": round(
                    run["peak_memory_mb"],
                    3,
                ),
            }
            for index, run in enumerate(runs, start=1)
        ],
    }


def write_csv(results: list[dict[str, Any]]) -> None:
    """Write a compact table suitable for later chart generation."""
    CSV_OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "multiplier",
        "event_count",
        "repetitions",
        "mean_elapsed_seconds",
        "median_elapsed_seconds",
        "elapsed_standard_deviation",
        "mean_throughput_events_per_second",
        "median_throughput_events_per_second",
        "mean_peak_memory_mb",
        "maximum_peak_memory_mb",
    ]

    with CSV_OUTPUT_FILE.open(
            "w",
            encoding="utf-8",
            newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for result in results:
            writer.writerow(
                {
                    field: result[field]
                    for field in fieldnames
                }
            )


def main() -> None:
    base_events = load_json(INPUT_FILE)
    context_profiles = load_json(CONTEXT_FILE)

    if not isinstance(base_events, list):
        raise ValueError(
            f"{INPUT_FILE} must contain a JSON list."
        )

    if not base_events:
        raise ValueError(
            f"{INPUT_FILE} does not contain any events."
        )

    if not isinstance(context_profiles, dict):
        raise ValueError(
            f"{CONTEXT_FILE} must contain a JSON object."
        )

    print("Experiment 4 - Performance and Scalability Evaluation")
    print("=" * 62)
    print(f"Base events: {len(base_events)}")
    print(f"Repetitions per workload: {REPETITIONS}")
    print()

    results: list[dict[str, Any]] = []

    for multiplier in WORKLOAD_MULTIPLIERS:
        synthetic_events = build_synthetic_dataset(
            base_events=base_events,
            multiplier=multiplier,
        )

        event_count = len(synthetic_events)

        print(
            f"Testing {event_count} events "
            f"({multiplier}x workload)..."
        )

        # Warm-up runs are not included in the recorded results.
        for _ in range(WARMUP_RUNS):
            process_events(
                events=synthetic_events,
                context_profiles=context_profiles,
            )

        measured_runs = [
            run_once(
                events=synthetic_events,
                context_profiles=context_profiles,
            )
            for _ in range(REPETITIONS)
        ]

        summary = summarise_runs(
            event_count=event_count,
            multiplier=multiplier,
            runs=measured_runs,
        )

        results.append(summary)

        print(
            "  Mean time:",
            f"{summary['mean_elapsed_seconds']:.6f} seconds",
        )
        print(
            "  Mean throughput:",
            f"{summary['mean_throughput_events_per_second']:.2f} "
            "events/second",
        )
        print(
            "  Mean peak memory:",
            f"{summary['mean_peak_memory_mb']:.3f} MB",
        )
        print()

    experiment_output = {
        "experiment": (
            "Experiment 4 - Performance and Scalability Evaluation"
        ),
        "methodology": {
            "input_file": str(INPUT_FILE),
            "context_file": str(CONTEXT_FILE),
            "base_event_count": len(base_events),
            "workload_multipliers": WORKLOAD_MULTIPLIERS,
            "repetitions_per_workload": REPETITIONS,
            "warmup_runs": WARMUP_RUNS,
            "timing_method": "time.perf_counter",
            "memory_method": "tracemalloc peak Python allocation",
            "processing_scope": [
                "context enrichment",
                "STRIDE mapping",
                "risk scoring",
                "priority assignment",
                "explanation generation",
                "risk-score sorting",
            ],
            "synthetic_scaling_note": (
                "Larger workloads were generated by duplicating the "
                "18-event normalised dataset while assigning unique "
                "event identifiers. Event characteristics were retained "
                "to provide a controlled and repeatable workload."
            ),
        },
        "results": results,
    }

    JSON_OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with JSON_OUTPUT_FILE.open(
            "w",
            encoding="utf-8",
    ) as file:
        json.dump(
            experiment_output,
            file,
            indent=4,
        )

    write_csv(results)

    print("=" * 62)
    print(f"Saved JSON results to {JSON_OUTPUT_FILE}")
    print(f"Saved CSV results to {CSV_OUTPUT_FILE}")


if __name__ == "__main__":
    main()