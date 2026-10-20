import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from networksecurity.url_triage import inspect_url, main


class UrlTriageTests(unittest.TestCase):
    def test_flags_without_echoing_secret(self):
        url = "http://user:password@192.0.2.10/path/secret?redirect=https%3A%2F%2Fother.test%2Ftoken"
        result = inspect_url(url, 1)
        codes = {item["code"] for item in result["flags"]}
        self.assertEqual(codes, {"plain-http", "userinfo", "ip-host", "nested-destination"})
        serialized = json.dumps(result)
        for secret in ("password", "path/secret", "other.test", "token"):
            self.assertNotIn(secret, serialized)

    def test_offline_cli_output(self):
        sample = Path(__file__).resolve().parents[1] / "examples" / "synthetic_urls.txt"
        with TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            self.assertEqual(main(["--input", str(sample), "--output", str(report_path)]), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["urls_checked"], 4)
            self.assertEqual(report["results"][0]["flags"], [])
            self.assertIn("punycode-host", {f["code"] for f in report["results"][2]["flags"]})


if __name__ == "__main__":
    unittest.main()
