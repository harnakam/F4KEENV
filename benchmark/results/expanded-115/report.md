# F4KEENV local shape benchmark

Fixed synthetic inputs; external credential verification disabled.

**Scope:** synthetic shape detection, not active credentials

**Sampling bias:** Catalog formats mostly originate from Gitleaks rules; this is not a representative scanner ranking.

| Scanner | Version | TP | FP | FN | TN | Unscored | Recall | Precision | FPR | Seconds |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gitleaks | 8.30.1 | 756 | 1 | 4 | 759 | 8 | 99.47% | 99.87% | 0.13% | 1.288 |
| trufflehog | trufflehog 3.99.8 | 200 | 0 | 560 | 760 | 8 | 26.32% | 100.00% | 0.00% | 1.599 |
| detect-secrets | 1.5.0 | 411 | 193 | 349 | 567 | 8 | 54.08% | 68.05% | 25.39% | 3.071 |

Metrics count any finding in a fixture; provider classification is separate. Exact source-rule scores are available for Gitleaks only.
Approximate Hypixel samples are unscored. Single-field inputs do not model all paired-credential requirements.
This is not a general scanner ranking. CPU time and peak RSS were not measured.
GitHub hosted results require a separate eligible private repository and are not inferred from these local runs.
