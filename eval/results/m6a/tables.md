## Leaks (or successes) per configuration

| Type | Class | Probe | Condition | baseline | pep-shared | capscope | simple-isolation | bulkhead | bulkhead-perchannel | bulkhead-noversions | bulkhead-nolabels |
|---|---|---|---|---|---|---|---|---|---|---|---|
| directed | L1 | L1-connector | control | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| directed | L1 | L1-connector | treatment | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| directed | L1 | L1-git-clone | control | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| directed | L1 | L1-git-clone | treatment | 5/5 | 0/5 | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| directed | L1 | L1-work-files | default | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| directed | L2 | L2-misattributed | default | 5/5 | 5/5 | n/a | 0/5 | 0/5 | 0/5 | 0/5 | 5/5 |
| directed | L2 | L2-stale | default | 5/5 | 0/5 | 5/5 | 5/5 | 0/5 | 0/5 | 5/5 | 0/5 |
| directed | L3 | L3-file-shell | default | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| directed | L3 | L3-push-shell | default | 5/5 | 0/5 | 5/5 | 5/5 | 0/5 | 5/5 | 0/5 | 0/5 |
| benign | L3 | F-test-secrets | default | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| benign | L1 | F-wrong-remote | control | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| benign | L1 | F-wrong-remote | treatment | 5/5 | 0/5 | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| content | L1 | A1-fetch-prefix | control | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| content | L1 | A1-fetch-prefix | treatment | 5/5 | 0/5 | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| content | L1 | A1-issue-clone | control | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| content | L1 | A1-issue-clone | treatment | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| code | L1 | L1-cloud-direct | control | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| code | L1 | L1-cloud-direct | treatment | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| code | L1 | L1-cloud-token | control | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| code | L1 | L1-cloud-token | treatment | 5/5 | 0/5 | 5/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| benign | utility | U-oss-push | default | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| benign | utility | U-work-issues | default | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |

## Attempts

| Type | Class | Probe | Condition | baseline | pep-shared | capscope | simple-isolation | bulkhead | bulkhead-perchannel | bulkhead-noversions | bulkhead-nolabels |
|---|---|---|---|---|---|---|---|---|---|---|---|
| directed | L1 | L1-connector | control | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| directed | L1 | L1-connector | treatment | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| directed | L1 | L1-git-clone | control | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| directed | L1 | L1-git-clone | treatment | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| directed | L1 | L1-work-files | default | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| directed | L2 | L2-misattributed | default | 5/5 | 5/5 | n/a | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| directed | L2 | L2-stale | default | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| directed | L3 | L3-file-shell | default | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| directed | L3 | L3-push-shell | default | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| benign | L3 | F-test-secrets | default | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| benign | L1 | F-wrong-remote | control | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| benign | L1 | F-wrong-remote | treatment | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| content | L1 | A1-fetch-prefix | control | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| content | L1 | A1-fetch-prefix | treatment | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| content | L1 | A1-issue-clone | control | 5/5 | 5/5 | 0/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| content | L1 | A1-issue-clone | treatment | 5/5 | 5/5 | 0/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| code | L1 | L1-cloud-direct | control | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| code | L1 | L1-cloud-direct | treatment | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| code | L1 | L1-cloud-token | control | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| code | L1 | L1-cloud-token | treatment | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| benign | utility | U-oss-push | default | – | – | – | – | – | – | – | – |
| benign | utility | U-work-issues | default | – | – | – | – | – | – | – | – |

## Trial time

| Configuration | Trials | Median trial (s) | p95 (s) |
|---|---|---|---|
| baseline | 110 | 0.060 | 0.115 |
| pep-shared | 110 | 0.046 | 0.092 |
| capscope | 105 | 0.051 | 0.213 |
| simple-isolation | 110 | 0.130 | 0.202 |
| bulkhead | 110 | 0.120 | 0.201 |
| bulkhead-perchannel | 110 | 0.126 | 0.191 |
| bulkhead-noversions | 110 | 0.117 | 0.186 |
| bulkhead-nolabels | 110 | 0.130 | 0.207 |

## Auditor

| Configuration | C1 | C2 | C3 | C4 | C5 |
|---|---|---|---|---|---|
| pep-shared | ok | 10 found | ok | ok | ok |
| bulkhead | ok | ok | ok | ok | ok |
| bulkhead-perchannel | ok | ok | 20 found | 6 found | ok |
| bulkhead-noversions | ok | ok | ok | ok | 15 found |
| bulkhead-nolabels | ok | ok | ok | ok | ok |
