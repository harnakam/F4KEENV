# F4KEENV local shape benchmark

Fixed synthetic inputs; external credential verification disabled.

**Scope:** synthetic shape detection, not active credentials

**Sampling bias:** Catalog formats mostly originate from Gitleaks rules; this is not a representative scanner ranking.

| Scanner | Version | TP | FP | FN | TN | Unscored | Recall | Precision | FPR | Seconds |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gitleaks | 8.30.1 | 1199 | 0 | 1 | 1200 | 100 | 99.92% | 100.00% | 0.00% | 1.386 |
| trufflehog | trufflehog 3.99.8 | 750 | 0 | 450 | 1200 | 100 | 62.50% | 100.00% | 0.00% | 1.696 |
| detect-secrets | 1.5.0 | 849 | 312 | 351 | 888 | 100 | 70.75% | 73.13% | 26.00% | 3.327 |

Metrics count any finding in a fixture; provider classification is separate. Exact source-rule scores are available for Gitleaks only.
Approximate Hypixel samples are unscored. Single-field inputs do not model all paired-credential requirements.
This is not a general scanner ranking. CPU time and peak RSS were not measured.
GitHub hosted results require a separate eligible private repository and are not inferred from these local runs.
