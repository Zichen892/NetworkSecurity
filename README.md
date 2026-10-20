# NetworkSecurity

**Offline phishing triage tools for defensive research and analyst review.** This repository offers two separate workflows: a passive review of suspicious URL structure, and a reproducible classifier for website features that have already been extracted. Neither workflow visits a website, scans a network, or declares a link safe.

> **中文导读：**本项目可以离线检查可疑链接的结构，也可以用仓库中的 30 维钓鱼网站特征数据训练和评估一个分类基线。URL 检查不会打开链接；模型不能直接接收一个网址。所有输出都应由安全分析人员复核，不能单独作为封禁或放行依据。

## Choose a workflow

| Workflow | Input | Output | Appropriate use |
| --- | --- | --- | --- |
| [Passive URL review](#1-review-suspicious-urls) | UTF-8 text file, one URL per line | JSON with hostnames and structural review flags | Initial sorting of links reported in a mailbox or ticket queue |
| [Feature classification](#2-classify-precomputed-features) | CSV with the 30 documented `-1/0/1` features | CSV with a score, predicted label, and model indicators | Research on already extracted website features |
| [Reproducible evaluation](#3-reproduce-the-benchmark) | Checked-in labeled CSV | JSON model and holdout metrics | Checking the baseline and its known error rates |

Python **3.9+** is required. The two core tools use only the standard library. Run the commands below from the repository root. No account, API key, browser extension, or network connection is needed.

## 1. Review suspicious URLs

The sample contains only synthetic or reserved domains:

```bash
python3 -m networksecurity.url_triage \
  --input examples/synthetic_urls.txt \
  --output url-report.json
```

Open the JSON report locally or see the [committed sample report](docs/example-url-report.json). A sample row with host `192.0.2.10` is flagged for plain HTTP and an IP-address host. The checks also look for userinfo before the host, punycode labels, long URLs, and nested destinations in redirect parameters.

The report omits URL paths, query values, and userinfo. It **does include the hostname**, which may itself be sensitive; review reports before sharing them. Keep the raw input file private. A URL with no flags is still **unverified**.

## 2. Classify precomputed features

The repository includes a [saved baseline model](models/phishing_nb.json), so this example runs without retraining:

```bash
python3 -m networksecurity.phishing predict \
  --input examples/sample_features.csv \
  --output predictions.csv
```

`predictions.csv` contains `row_number`, `phishing_probability`, `predicted_label`, and `top_phishing_indicators`. For example, the first sample row produces a phishing score of `0.998881`; this row is for demonstrating the command and is **not an independent test case**. The indicators name feature values that most favor the phishing class in this model. They are not causal explanations, and the probabilities are not calibrated for current websites.

The input must have exactly the 30 columns shown in [sample_features.csv](examples/sample_features.csv), in that order, with values from `-1`, `0`, and `1`. It must **not** contain the `Result` column. This tool does not turn a pasted URL into those features.

To change the decision threshold, use `--threshold 0.7` (a number strictly between `0` and `1`). A higher threshold usually reduces alerts while potentially increasing missed phishing cases; evaluate that tradeoff on data appropriate to your setting.

## 3. Reproduce the benchmark

```bash
python3 -m networksecurity.phishing train
python3 -m unittest discover -s tests -v
```

Training writes [models/phishing_nb.json](models/phishing_nb.json) and [docs/evaluation.json](docs/evaluation.json). The model is categorical Naive Bayes with Laplace smoothing. `Result = -1` is treated as phishing and `Result = 1` as legitimate.

The evaluation uses seed `42`, a `0.5` decision threshold, and a 20% holdout of **unique feature vectors**. Identical vectors stay on one side of the split to avoid exact duplicate leakage. This matters because the CSV contains 11,055 rows but only 5,785 distinct vectors; 64 vectors even have conflicting labels.

| Holdout measure | Result |
| --- | ---: |
| Rows | 2,112 |
| Accuracy | 93.18% |
| Phishing precision | 92.98% |
| Phishing recall | 90.68% |
| Phishing F1 | 91.82% |
| False negatives: phishing labeled legitimate | 83 |
| False positives: legitimate labeled phishing | 61 |
| Training-majority-class baseline accuracy | 57.81% |

The saved model is refit on all 11,055 rows **after** holdout evaluation; the table measures the model trained only on the training partition. Grouping exact duplicates removes one source of optimistic results, but related websites or collection campaigns may still span partitions: the CSV has no URL, domain, or capture-time identifiers. These are benchmark results on a historical dataset, **not measured protection on current phishing sites**.

## Analyst workflow and safety boundaries

1. Receive a suspicious link through an authorized reporting channel. Store the raw link privately; it may contain tokens or personal data.
2. Run passive URL review locally. Treat every flag as a prompt for investigation, not a verdict.
3. If the 30 features were independently collected through an approved process, run feature classification and review the result alongside other evidence.
4. Record the analyst conclusion, false positives, false negatives, and any defensive action. Use [the case-study template](docs/defensive-work-template.md) for real, authorized work.

The tools do not fetch links, follow redirects, resolve DNS, extract page content, or replace browser protection and threat intelligence. Do not use a high score alone to block a site, or a low score to tell someone a link is safe.

## Dataset and provenance

The checked-in [phisingData.csv](Network_Data/phisingData.csv) has the 11,055 rows and 30-feature schema of the [UCI Phishing Websites dataset](https://archive.ics.uci.edu/dataset/327/phishing). The original repository upload did not record this CSV copy's exact lineage. [DATASET.md](DATASET.md) documents the attribution and uncertainty; UCI publishes its dataset under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). This is a historical research dataset, not a live threat feed.

## Optional installation and MongoDB import

The module commands above need no installation. To add the `phishing-triage` and `url-triage` command names to your environment:

```bash
python3 -m pip install .
phishing-triage --help
url-triage --help
```

The legacy MongoDB import is separate from both defensive tools. By default it only checks the local CSV and counts rows:

```bash
python3 push_data.py
```

To insert records, install the optional driver, provide `MONGO_DB_URL` through your shell or a secrets manager, and explicitly pass `--write`:

```bash
python3 -m pip install '.[mongo]'
python3 push_data.py --write --database network_security --collection phishing_features
```

Repeated writes insert duplicate records. Do not put a connection string in source code or public logs. `python3 test_mongodb.py` is an opt-in connection check and also requires `MONGO_DB_URL`.

## Repository guide

| Path | Purpose |
| --- | --- |
| [`networksecurity/url_triage.py`](networksecurity/url_triage.py) | Passive URL parsing and redacted JSON report |
| [`networksecurity/phishing.py`](networksecurity/phishing.py) | Feature validation, training, evaluation, and prediction |
| [`docs/evaluation.json`](docs/evaluation.json) | Reproducible holdout metrics and dataset hash |
| [`models/phishing_nb.json`](models/phishing_nb.json) | Saved, inspectable baseline model |
| [`tests/`](tests/) | Unit and reproducibility checks |
| [`SECURITY.md`](SECURITY.md) | Private security issue reporting guidance |

For a portfolio or access-program application, link to this repository **and** to evidence of defensive work you actually performed: your authorized scope, findings, fixes, and retest. A benchmark score or synthetic demo alone does not establish operational experience or program eligibility.

**License:** code is [MIT](LICENSE); dataset attribution and license are in [DATASET.md](DATASET.md).
