"""Offline phishing-feature triage and reproducible baseline evaluation.

This module never fetches a URL. It accepts only the precomputed feature schema
from the UCI Phishing Websites dataset used by this repository.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import sys
from typing import Any


FEATURES = tuple("""having_IP_Address URL_Length Shortining_Service having_At_Symbol
double_slash_redirecting Prefix_Suffix having_Sub_Domain SSLfinal_State
Domain_registeration_length Favicon port HTTPS_token Request_URL URL_of_Anchor
Links_in_tags SFH Submitting_to_email Abnormal_URL Redirect on_mouseover
RightClick popUpWidnow Iframe age_of_domain DNSRecord web_traffic Page_Rank
Google_Index Links_pointing_to_page Statistical_report""".split())
VALUES = (-1, 0, 1)
LABELS = (-1, 1)  # UCI convention: -1 phishing, 1 legitimate.
MODEL_VERSION = 1


def _read_rows(path: Path, labeled: bool) -> list[tuple[tuple[int, ...], int | None]]:
    expected = list(FEATURES) + (["Result"] if labeled else [])
    rows: list[tuple[tuple[int, ...], int | None]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != expected:
            raise ValueError("CSV columns must match the 30 UCI features in their documented order"
                             + (" followed by Result" if labeled else " (without Result)"))
        for line_number, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(f"Too many CSV columns on line {line_number}")
            try:
                features = tuple(int(row[name]) for name in FEATURES)
                label = int(row["Result"]) if labeled else None
            except (ValueError, TypeError, KeyError) as exc:
                raise ValueError(f"Invalid integer on CSV line {line_number}") from exc
            if any(value not in VALUES for value in features):
                raise ValueError(f"Feature outside -1, 0, 1 on CSV line {line_number}")
            if labeled and label not in LABELS:
                raise ValueError(f"Result must be -1 or 1 on CSV line {line_number}")
            rows.append((features, label))
    if not rows:
        raise ValueError("CSV has no data rows")
    return rows


def grouped_split(
    rows: list[tuple[tuple[int, ...], int]], test_fraction: float, seed: int
) -> tuple[list[tuple[tuple[int, ...], int]], list[tuple[tuple[int, ...], int]], int]:
    """Keep identical feature vectors together to prevent exact-duplicate leakage."""
    if not 0 < test_fraction < 1:
        raise ValueError("test_fraction must be between 0 and 1")
    groups: dict[tuple[int, ...], list[tuple[tuple[int, ...], int]]] = defaultdict(list)
    for row in rows:
        groups[row[0]].append(row)
    keys = sorted(groups)
    if len(keys) < 2:
        raise ValueError("At least two distinct feature vectors are needed")
    random.Random(seed).shuffle(keys)
    test_groups = max(1, min(len(keys) - 1, round(len(keys) * test_fraction)))
    test_keys = set(keys[:test_groups])
    training = [row for row in rows if row[0] not in test_keys]
    testing = [row for row in rows if row[0] in test_keys]
    return training, testing, len(keys)


def fit(rows: list[tuple[tuple[int, ...], int]]) -> dict[str, Any]:
    class_counts = Counter(label for _, label in rows)
    if any(class_counts[label] == 0 for label in LABELS):
        raise ValueError("Training data must contain both phishing and legitimate labels")
    value_counts = {label: [Counter() for _ in FEATURES] for label in LABELS}
    for features, label in rows:
        for index, value in enumerate(features):
            value_counts[label][index][value] += 1
    return {
        "format_version": MODEL_VERSION,
        "algorithm": "categorical_naive_bayes_laplace_1",
        "feature_names": list(FEATURES),
        "label_mapping": {"-1": "phishing", "1": "legitimate"},
        "class_counts": {str(label): class_counts[label] for label in LABELS},
        "value_counts": {
            str(label): [
                {str(value): counter[value] for value in VALUES}
                for counter in value_counts[label]
            ] for label in LABELS
        },
    }


def _validate_model(model: dict[str, Any]) -> None:
    if (model.get("format_version") != MODEL_VERSION or
            model.get("feature_names") != list(FEATURES) or
            model.get("algorithm") != "categorical_naive_bayes_laplace_1"):
        raise ValueError("Unsupported model format or feature schema")
    try:
        for label in LABELS:
            count = model["class_counts"][str(label)]
            counters = model["value_counts"][str(label)]
            if not isinstance(count, int) or count <= 0 or len(counters) != len(FEATURES):
                raise ValueError("Invalid model counts")
            for counter in counters:
                values = [counter[str(value)] for value in VALUES]
                if any(not isinstance(value, int) or value < 0 for value in values):
                    raise ValueError("Invalid model counts")
                if sum(values) != count:
                    raise ValueError("Invalid model counts")
    except (KeyError, TypeError) as exc:
        raise ValueError("Invalid model counts") from exc


def phishing_probability(model: dict[str, Any], features: tuple[int, ...]) -> float:
    if len(features) != len(FEATURES) or any(value not in VALUES for value in features):
        raise ValueError("Input must contain 30 feature values from -1, 0, 1")
    counts = model["class_counts"]
    total = counts["-1"] + counts["1"]
    scores = {}
    for label in LABELS:
        class_count = counts[str(label)]
        score = math.log((class_count + 1) / (total + 2))
        for index, value in enumerate(features):
            observed = model["value_counts"][str(label)][index][str(value)]
            score += math.log((observed + 1) / (class_count + 3))
        scores[label] = score
    difference = scores[1] - scores[-1]
    if difference >= 0:
        exp_neg = math.exp(-difference)
        return exp_neg / (1 + exp_neg)
    exp_pos = math.exp(difference)
    return 1 / (1 + exp_pos)


def top_phishing_indicators(model: dict[str, Any], features: tuple[int, ...], limit: int = 3) -> list[str]:
    """Return features whose observed values most favor the phishing class in this model."""
    phishing_count = model["class_counts"]["-1"]
    legitimate_count = model["class_counts"]["1"]
    contributions = []
    for index, value in enumerate(features):
        phishing_hits = model["value_counts"]["-1"][index][str(value)]
        legitimate_hits = model["value_counts"]["1"][index][str(value)]
        contribution = math.log((phishing_hits + 1) / (phishing_count + 3)) - math.log(
            (legitimate_hits + 1) / (legitimate_count + 3))
        if contribution > 0:
            contributions.append((contribution, FEATURES[index]))
    contributions.sort(reverse=True)
    return [name for _, name in contributions[:limit]]


def evaluate(model: dict[str, Any], rows: list[tuple[tuple[int, ...], int]], threshold: float) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for features, actual in rows:
        predicted = -1 if phishing_probability(model, features) >= threshold else 1
        if actual == -1 and predicted == -1:
            tp += 1
        elif actual == 1 and predicted == -1:
            fp += 1
        elif actual == 1 and predicted == 1:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "samples": len(rows),
        "actual_phishing": tp + fn,
        "actual_legitimate": tn + fp,
        "confusion_matrix": {"true_positive": tp, "false_positive": fp,
                             "true_negative": tn, "false_negative": fn},
        "accuracy": (tp + tn) / len(rows),
        "phishing_precision": precision,
        "phishing_recall": recall,
        "phishing_f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
    }


def train(data: Path, model_out: Path, report_out: Path, seed: int, threshold: float) -> dict[str, Any]:
    if not 0 < threshold < 1:
        raise ValueError("threshold must be between 0 and 1")
    rows = _read_rows(data, labeled=True)
    training, testing, unique_vectors = grouped_split(rows, test_fraction=0.2, seed=seed)
    group_labels: dict[tuple[int, ...], set[int]] = defaultdict(set)
    for features, label in rows:
        group_labels[features].add(label)
    holdout_model = fit(training)
    metrics = evaluate(holdout_model, testing, threshold)
    train_labels = Counter(label for _, label in training)
    majority_label = max(LABELS, key=lambda label: train_labels[label])
    baseline_correct = sum(label == majority_label for _, label in testing)
    final_model = fit(rows)  # The saved model uses all rows after holdout evaluation.
    final_model["training_data_sha256"] = hashlib.sha256(data.read_bytes()).hexdigest()
    final_model["trained_rows"] = len(rows)
    report = {
        "dataset": "UCI Phishing Websites (repository CSV copy)",
        "dataset_sha256": final_model["training_data_sha256"],
        "method": "Categorical Naive Bayes with Laplace smoothing; 80/20 seeded split by unique feature vector",
        "seed": seed,
        "phishing_label": -1,
        "threshold": threshold,
        "total_rows": len(rows),
        "unique_feature_vectors": unique_vectors,
        "duplicate_feature_rows": len(rows) - unique_vectors,
        "feature_vectors_with_conflicting_labels": sum(len(labels) > 1 for labels in group_labels.values()),
        "training_rows": len(training),
        "holdout_rows": len(testing),
        "holdout": metrics,
        "training_majority_class_baseline_accuracy": baseline_correct / len(testing),
        "saved_model_note": "Saved model is refit on all rows after holdout evaluation; holdout metrics are from the training-only model.",
    }
    model_out.parent.mkdir(parents=True, exist_ok=True)
    report_out.parent.mkdir(parents=True, exist_ok=True)
    model_out.write_text(json.dumps(final_model, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def predict(model_path: Path, input_path: Path, output_path: Path, threshold: float) -> int:
    if not 0 < threshold < 1:
        raise ValueError("threshold must be between 0 and 1")
    model = json.loads(model_path.read_text(encoding="utf-8"))
    if not isinstance(model, dict):
        raise ValueError("Model must be a JSON object")
    _validate_model(model)
    rows = _read_rows(input_path, labeled=False)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["row_number", "phishing_probability", "predicted_label", "top_phishing_indicators"])
        for number, (features, _) in enumerate(rows, start=1):
            score = phishing_probability(model, features)
            indicators = ";".join(top_phishing_indicators(model, features))
            writer.writerow([number, f"{score:.6f}", "phishing" if score >= threshold else "legitimate", indicators])
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline triage of precomputed phishing website features")
    sub = parser.add_subparsers(dest="command", required=True)
    train_parser = sub.add_parser("train", help="Fit a model and write holdout metrics")
    train_parser.add_argument("--data", type=Path, default=Path("Network_Data/phisingData.csv"))
    train_parser.add_argument("--model-out", type=Path, default=Path("models/phishing_nb.json"))
    train_parser.add_argument("--report-out", type=Path, default=Path("docs/evaluation.json"))
    train_parser.add_argument("--seed", type=int, default=42)
    train_parser.add_argument("--threshold", type=float, default=0.5)
    predict_parser = sub.add_parser("predict", help="Classify feature rows without network requests")
    predict_parser.add_argument("--model", type=Path, default=Path("models/phishing_nb.json"))
    predict_parser.add_argument("--input", type=Path, required=True)
    predict_parser.add_argument("--output", type=Path, required=True)
    predict_parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args(argv)
    try:
        if args.command == "train":
            report = train(args.data, args.model_out, args.report_out, args.seed, args.threshold)
            print(json.dumps(report["holdout"], indent=2))
        else:
            count = predict(args.model, args.input, args.output, args.threshold)
            print(f"Wrote {count} predictions to {args.output}")
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"phishing-triage: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
