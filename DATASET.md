# Dataset attribution and provenance

The file `Network_Data/phisingData.csv` was already in this repository. It contains 11,055 rows, 30 integer features, and a `Result` label. These dimensions and column names match the [UCI Machine Learning Repository's Phishing Websites dataset](https://archive.ics.uci.edu/dataset/327/phishing) (dataset ID 327). The original repository did not document where this particular CSV copy came from, so exact file lineage has not been independently verified.

Please credit the dataset as:

> Mohammad, R. & McCluskey, L. (2012). *Phishing Websites* [Dataset]. UCI Machine Learning Repository. https://doi.org/10.24432/C51W2X.

UCI lists the dataset under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). The repository copy is a CSV with feature names and rows; the original UCI distribution includes an ARFF file and feature documentation. We have not changed the checked-in CSV as part of this update.

The data was donated in 2015 and is not a current phishing feed. It contains precomputed features rather than raw URLs, so this tool cannot extract the required features from an arbitrary link. The target mapping used by the baseline is `-1 = phishing` and `1 = legitimate`; the training code validates both labels and all feature values before fitting.
