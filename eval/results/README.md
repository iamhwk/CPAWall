# Records of the evaluation

- `m6a/`: the first scripted campaign (875 trials).
- `m6b/`: the model-driven trials (`results.jsonl.gz`; tables in
  `tables.md`), the scripted campaign rerun after the vault fix
  (`scripted/`, 915 trials), and the per-action costs (`bench.json`);
  `meta.json` describes the runs.
- `m6c/`: load, scaling, and the replay of the model-driven trials' tool
  calls (`scale.json`; tables in `tables.md`).

In the records under `m6b/`, the working folder of the runs is written as
`/work`: its absolute path on the first host was replaced after the runs,
and nothing else was changed.
