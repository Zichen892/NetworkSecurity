# NetworkSecurity: offline phishing-feature triage

This repository provides two **offline defensive triage** workflows: a reproducible classifier for precomputed phishing website features, and a passive URL structure review for suspicious links. Neither workflow visits URLs or blocks traffic. Their outputs are signals for a human analyst to review.

## What changed

- Runnable `train` and `predict` commands with no runtime dependencies.
- A deterministic holdout evaluation that keeps identical feature vectors on the same side of the split. This matters here: the checked-in CSV has many repeated vectors.
- A saved JSON model and evaluation report, plus input validation and automated tests.
- A URL review command that checks link structure without fetching the destination or reporting path/query values.
- Optional MongoDB import defaults to a dry run and never prints connection credentials or all records.
- Dataset attribution and explicit limits for security use.

## Quick start

Requires Python 3.9 or newer. Run from the repository root:

```bash
python3 -m networksecurity.phishing train
python3 -m networksecurity.phishing predict \
  --input examples/sample_features.csv \
  --output predictions.csv
```

The first command writes [the model](models/phishing_nb.json) and [evaluation report](docs/evaluation.json). The second writes `row_number`, `phishing_probability`, `predicted_label`, and three model indicators to `predictions.csv`. Indicators are the observed features that most favor the phishing class in this model; they are not causal explanations. Input for prediction must have exactly the 30 feature columns in [the sample](examples/sample_features.csv), without `Result`. It does **not** accept a URL by itself.

Optional package installation provides the `phishing-triage` and `url-triage` commands:

```bash
python3 -m pip install .
phishing-triage train
```

## Passive URL review

For links reported through a mailbox or ticket queue, place one URL per line in a private UTF-8 text file. The example uses only reserved/synthetic domains:

```bash
python3 -m networksecurity.url_triage \
  --input examples/synthetic_urls.txt \
  --output url-report.json
```

The JSON report gives a host and review flags for each line. Checks include HTTP transport, userinfo before the host, IP-address hosts, punycode labels, very long URLs, and nested destinations in redirect parameters. It omits URL paths, query values, and userinfo. A clean report **does not mean a link is safe**. The input file itself may contain credentials or personal data; keep it private and do not commit it. See [the synthetic report](docs/example-url-report.json).

## Reproducible evaluation

The committed [evaluation report](docs/evaluation.json) was generated with seed `42`, a 20% holdout of unique feature vectors, and a phishing decision threshold of `0.5`. The **phishing** class is `Result = -1`; `Result = 1` means **legitimate**. The model uses categorical likelihoods for feature values `-1`, `0`, and `1` with Laplace smoothing.

| Holdout measure | Result |
| --- | ---: |
| Rows | 2,112 |
| Accuracy | 93.18% |
| Phishing precision | 92.98% |
| Phishing recall | 90.68% |
| Phishing F1 | 91.82% |
| False negatives (phishing classified legitimate) | 83 |
| False positives (legitimate classified phishing) | 61 |

These are **benchmark results on this historical dataset**, not a measured detection rate on current websites. The saved model is refit on all 11,055 rows after the holdout run; the table evaluates the training-only model. The feature CSV has 5,785 distinct vectors and 64 vectors with conflicting labels. Grouping exact duplicates avoids one source of evaluation leakage, but websites or collection campaigns may still be related across the split because the file has no URL, domain, or collection-time identifiers. The model probabilities are not calibrated. A production assessment needs newer, independently sourced data and review of false negatives.

## Data and scope

The checked-in [CSV](Network_Data/phisingData.csv) has the 11,055 rows and 30-feature schema described by the [UCI Phishing Websites dataset](https://archive.ics.uci.edu/dataset/327/phishing). The repository's original upload did not record its provenance, so [DATASET.md](DATASET.md) explains the attribution and uncertainty. The UCI dataset is published under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

The model is a defensive research baseline for classifying **already extracted** features. URL review provides only lexical flags. Neither workflow can decide whether a pasted link is safe, inspect a live site, or replace browser protection, threat intelligence, and analyst review. Do not use their output as the sole reason to block a domain or declare one safe.

## Optional MongoDB import

The legacy data-import workflow remains available, but it is optional and does not run during training or prediction. By default, it only counts rows:

```bash
python3 push_data.py
```

To insert the dataset, install the optional dependency, set `MONGO_DB_URL` in your shell or a secrets manager, and explicitly pass `--write`:

```bash
python3 -m pip install '.[mongo]'
python3 push_data.py --write --database network_security --collection phishing_features
```

Repeated `--write` runs insert duplicate rows. Avoid using production credentials for a local experiment. The connection check `python3 test_mongodb.py` also requires `MONGO_DB_URL` and runs only when invoked.

## Development and responsible use

```bash
python3 -m unittest discover -s tests -v
```

See [SECURITY.md](SECURITY.md) for private issue reporting and [the case-study template](docs/defensive-work-template.md) for documenting an actual authorized defensive use. This repository alone does not demonstrate active security operations or guarantee eligibility for any access program; cite only work you have really performed.

## License

Code: [MIT](LICENSE). Dataset: see [DATASET.md](DATASET.md).
