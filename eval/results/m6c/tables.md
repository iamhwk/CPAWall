# Load and scalability

Machine: 2 vCPUs (Intel(R) Xeon(R) Processor @ 2.30GHz), 7.8 GB, kernel 6.18.44-fc-v310, Python 3.13.17, Landlock ABI 7.

## Throughput through one project's PEP

Clients in their own processes, each sending GET requests for the duration; `keep`: one connection per client, `new`: a new connection (CONNECT and TLS) per request. Latencies in ms; core CPU in ms per request.

| mode | clients | where | req/s | p50 | p95 | p99 | core CPU/req | core CPU util. |
|---|---|---|---|---|---|---|---|---|
| keep | 1 | direct | 5596.4 | 0.165 | 0.232 | 0.372 | 0.0 | 0.0 |
| keep | 1 | bulkhead | 2075.8 | 0.425 | 0.721 | 1.006 | 0.347 | 0.713 |
| keep | 2 | direct | 5407.2 | 0.358 | 0.529 | 0.807 | 0.0 | 0.0 |
| keep | 2 | bulkhead | 1886.0 | 0.952 | 1.894 | 2.424 | 0.424 | 0.791 |
| keep | 4 | direct | 6588.6 | 0.471 | 1.368 | 1.905 | 0.0 | 0.0 |
| keep | 4 | bulkhead | 1840.6 | 2.106 | 3.263 | 4.112 | 0.428 | 0.768 |
| keep | 8 | direct | 5170.0 | 1.36 | 3.179 | 4.055 | 0.0 | 0.0 |
| keep | 8 | bulkhead | 1981.8 | 3.917 | 5.888 | 7.266 | 0.409 | 0.781 |
| keep | 16 | direct | 3602.6 | 4.139 | 5.672 | 7.022 | 0.0 | 0.0 |
| keep | 16 | bulkhead | 2058.4 | 7.679 | 10.841 | 21.13 | 0.398 | 0.76 |
| keep | 32 | direct | 3966.2 | 7.495 | 9.823 | 12.3 | 0.0 | 0.0 |
| keep | 32 | bulkhead | 3004.8 | 10.779 | 15.093 | 32.681 | 0.272 | 0.723 |
| new | 1 | direct | 709.0 | 1.388 | 1.666 | 1.929 | 0.0 | 0.0 |
| new | 1 | bulkhead | 251.2 | 4.042 | 4.678 | 5.504 | 2.834 | 0.706 |
| new | 2 | direct | 1049.6 | 1.808 | 2.635 | 3.113 | 0.0 | 0.0 |
| new | 2 | bulkhead | 353.4 | 5.363 | 7.51 | 9.076 | 2.434 | 0.852 |
| new | 4 | direct | 862.8 | 4.405 | 7.496 | 9.538 | 0.0 | 0.0 |
| new | 4 | bulkhead | 389.0 | 9.922 | 14.17 | 17.766 | 2.17 | 0.831 |
| new | 8 | direct | 957.8 | 6.893 | 11.424 | 14.044 | 0.0 | 0.0 |
| new | 8 | bulkhead | 319.6 | 25.022 | 30.941 | 35.302 | 2.516 | 0.773 |
| new | 16 | direct | 702.2 | 10.048 | 17.561 | 1019.986 | 0.0 | 0.0 |
| new | 16 | bulkhead | 316.6 | 46.846 | 59.122 | 65.015 | 2.268 | 0.606 |
| new | 32 | direct | 817.6 | 9.755 | 18.424 | 1035.967 | 0.0 | 0.0 |
| new | 32 | bulkhead | 331.8 | 82.707 | 113.551 | 1077.054 | 2.104 | 0.608 |

## Active projects

Every project's partition started; then every project sends requests at once (one keep-alive client each).

| projects | start ms (median) | PSS MB per partition | PSS MB, all | core MB added | idle core CPU | req/s, all | req/s per project (min-max) | p50 ms | p95 ms |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 27.497 | 9.75 | 9.8 | -0.29 | 0.0 | 1646.8 | 1646.8-1646.8 | 0.57 | 0.762 |
| 2 | 27.696 | 8.97 | 17.9 | 0.18 | 0.0 | 2066.2 | 1032.4-1033.8 | 0.903 | 1.612 |
| 4 | 26.895 | 8.21 | 32.8 | 1.54 | 0.0 | 1997.4 | 492.2-504.2 | 1.903 | 3.208 |
| 8 | 25.713 | 7.68 | 61.4 | -3.25 | 0.0 | 2029.4 | 249.8-257.4 | 3.833 | 5.836 |
| 16 | 26.268 | 7.34 | 117.3 | 8.08 | 0.0 | 2163.8 | 132.8-138.2 | 7.168 | 9.992 |
| 32 | 26.11 | 7.14 | 228.4 | 15.96 | 0.0 | 2293.6 | 56.8-76.2 | 13.222 | 18.917 |

## Policy size

| repositories | entries | check items | compile s | decide us, uncached | decide us, cached |
|---|---|---|---|---|---|
| 10 | 20 | 25 | 0.0051 | 1.64 | 0.41 |
| 30 | 60 | 65 | 0.009 | 3.9 | 0.42 |
| 100 | 200 | 205 | 0.083 | 232.5 | 0.53 |
| 300 | 600 | 605 | 0.8149 | 1468.53 | 0.73 |
| 1000 | 2000 | 2005 | 10.2548 | 5754.85 | 0.73 |
| 3000 | 6000 | 6005 | 90.7418 | 16636.4 | 0.65 |

## Log and audit

| checkpoint every | appends/s | us/append | bytes/record |
|---|---|---|---|
| 50 | 42338 | 23.6 | 664.4 |
| 0 | 44861 | 22.3 | 664.4 |

| records | service records | log MB | C1 s | C2 s | C3 s | C4 s | C5 s | total s | problems |
|---|---|---|---|---|---|---|---|---|---|
| 1000 | 614 | 0.54 | 0.012 | 0.007 | 0.002 | 0.001 | 0.0 | 0.022 | 0 |
| 10000 | 6218 | 5.42 | 0.136 | 0.05 | 0.011 | 0.005 | 0.003 | 0.205 | 0 |
| 100000 | 62310 | 54.44 | 1.423 | 0.521 | 0.126 | 0.09 | 0.07 | 2.23 | 0 |

## Session operations (ms)

| switch (median) | switch (p95) | compile | install |
|---|---|---|---|
| 0.094 | 0.145 | 0.432 | 0.779 |

## Work inside a partition (ms, median)

| workload | outside | inside | overhead % |
|---|---|---|---|
| files | 64.836 | 64.38 | -0.7 |
| git | 9.551 | 9.453 | -1.0 |
| exec | 136.652 | 128.377 | -6.1 |
| cpu | 96.488 | 93.475 | -3.1 |

## Replay of the model-driven utility trials (medians per trial)

Each configuration replays the tool calls recorded in it, three times; harness time includes starting and stopping partitions.

| model | configuration | task | trials | calls | succeeded | tool time ms | first call ms | harness time ms | with the model (M6b) s |
|---|---|---|---|---|---|---|---|---|---|
| claude-haiku-5-5 | baseline | MU-oss-feature | 15 | 8 | 15 | 157.9 | 9.4 | 158.0 | 9.219 |
| claude-haiku-5-5 | baseline | MU-work-issues | 15 | 1 | 15 | 2.92 | 2.92 | 3.0 | 2.373 |
| claude-haiku-5-5 | bulkhead | MU-oss-feature | 15 | 5 | 15 | 162.34 | 10.68 | 202.0 | 7.816 |
| claude-haiku-5-5 | bulkhead | MU-work-issues | 15 | 1 | 15 | 46.54 | 46.54 | 83.0 | 2.138 |
| claude-sonnet-5-5 | baseline | MU-oss-feature | 15 | 8 | 15 | 111.13 | 7.65 | 111.0 | 14.14 |
| claude-sonnet-5-5 | baseline | MU-work-issues | 15 | 1 | 15 | 2.86 | 2.86 | 3.0 | 2.305 |
| claude-sonnet-5-5 | bulkhead | MU-oss-feature | 15 | 4 | 15 | 114.28 | 7.94 | 155.0 | 9.772 |
| claude-sonnet-5-5 | bulkhead | MU-work-issues | 15 | 1 | 15 | 45.69 | 45.69 | 82.0 | 2.26 |

## Request rate of the model-driven agents (M6b, under bulkhead)

HTTP requests through the project's PEP per second of a trial, over the trials that made at least one.

| model | trials | median req/s | max req/s |
|---|---|---|---|
| claude-haiku-5-5 | 40 | 0.295 | 0.517 |
| claude-sonnet-5-5 | 39 | 0.247 | 0.457 |

