import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from networksecurity.phishing import FEATURES, grouped_split, predict, train


ROOT = Path(__file__).resolve().parents[1]


class PhishingTests(unittest.TestCase):
    def test_grouped_split_keeps_duplicate_vectors_together(self):
        a, b, c = (tuple([value] * len(FEATURES)) for value in (-1, 0, 1))
        rows = [(a, -1), (a, -1), (b, 1), (c, -1), (c, 1)]
        training, testing, groups = grouped_split(rows, 0.33, 42)
        self.assertEqual(groups, 3)
        self.assertFalse({row[0] for row in training} & {row[0] for row in testing})
        self.assertEqual(len(training) + len(testing), len(rows))

    def test_committed_evaluation_is_reproducible(self):
        with TemporaryDirectory() as directory:
            model_path = Path(directory) / "model.json"
            report_path = Path(directory) / "report.json"
            report = train(ROOT / "Network_Data" / "phisingData.csv", model_path, report_path, 42, 0.5)
            expected = json.loads((ROOT / "docs" / "evaluation.json").read_text())
            self.assertEqual(report["dataset_sha256"], expected["dataset_sha256"])
            self.assertEqual(report["holdout"]["confusion_matrix"], expected["holdout"]["confusion_matrix"])
            self.assertAlmostEqual(report["holdout"]["phishing_f1"], expected["holdout"]["phishing_f1"])
            self.assertEqual(json.loads(model_path.read_text()),
                             json.loads((ROOT / "models" / "phishing_nb.json").read_text()))
            self.assertEqual(report["holdout"]["confusion_matrix"]["false_negative"], 83)

    def test_prediction_emits_only_row_and_score(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "predictions.csv"
            count = predict(ROOT / "models" / "phishing_nb.json",
                            ROOT / "examples" / "sample_features.csv", output, 0.5)
            with output.open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(count, 3)
            self.assertEqual(len(rows), 3)
            self.assertEqual(set(rows[0]), {"row_number", "phishing_probability", "predicted_label",
                                            "top_phishing_indicators"})
            self.assertTrue(all(0 <= float(row["phishing_probability"]) <= 1 for row in rows))

    def test_rejects_wrong_schema(self):
        with TemporaryDirectory() as directory:
            invalid = Path(directory) / "bad.csv"
            invalid.write_text("url,Result\nhttps://example.test,-1\n")
            with self.assertRaises(ValueError):
                train(invalid, Path(directory) / "model.json", Path(directory) / "report.json", 42, 0.5)


if __name__ == "__main__":
    unittest.main()
