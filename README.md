# Explainable Network Exposure Benchmark

[![CI](https://github.com/soin8293/explainable-network-exposure-benchmark/actions/workflows/ci.yml/badge.svg)](https://github.com/soin8293/explainable-network-exposure-benchmark/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small, transparent, entirely synthetic benchmark for cautious explanations of
network-exposure evidence. It tests whether an explanation stays faithful to
observed ports, avoids unsupported vulnerability claims, states scope
limitations, recommends owner-approved verification, and ignores a
prompt-injection canary.

This is an evaluation prototype—not a scanner, vulnerability detector,
production assurance tool, or peer-reviewed result.

## Why this project

Security explanations can sound confident while silently inventing facts. This
repository makes five desirable behaviors executable and reviewable. The rules,
fixtures, detailed findings, and baseline outputs are all version controlled.

## Quickstart

```bash
git clone https://github.com/soin8293/explainable-network-exposure-benchmark.git
cd explainable-network-exposure-benchmark
python -m pip install -e '.[dev]'
exposure-benchmark
pytest -q
```

The default generator is deterministic and offline. It writes:

- `results/local-baseline.json` with dimension and case-level findings
- `results/local-baseline.csv` for quick analysis

## Optional OpenAI comparison

```bash
python -m pip install -e '.[openai]'
export OPENAI_API_KEY="your-project-key"
exposure-benchmark --generator openai --model "your-explicit-model" \
  --json-output results/model-run.json --csv-output results/model-run.csv
```

The adapter uses the OpenAI Responses API, reads credentials from the
environment, requires an explicit model for reportability, sends no real scan
data, and sets `store=False`. See the official
[OpenAI Responses API documentation](https://developers.openai.com/api/reference/cli/resources/responses/methods/create).

Do not commit credentials or unreviewed model outputs. API availability, model
access, cost, and retention controls depend on the operator's account and
settings.

## Results and interpretation

The committed deterministic baseline is a software regression check. A score
of 100 means only that the local generator satisfies these six fixtures and
transparent rules; it is not evidence of real-world model safety.

Read [`docs/methodology.md`](docs/methodology.md) before reporting results and
[`docs/threat-model.md`](docs/threat-model.md) before adding data or generators.

## Project structure

```text
exposure_benchmark/   evaluator, generators, and CLI
exposure_benchmark/fixtures/  six synthetic cases packaged with the CLI
tests/                evaluator and end-to-end regression tests
results/              committed deterministic baseline
docs/                 methodology and threat model
```

## Responsible use and attribution

Use only synthetic or explicitly authorized data in derivative experiments.
Report the exact fixture commit, generator/model, prompt, dependency versions,
and date. Cite the repository using `CITATION.cff` and disclose material AI
assistance in derivative work.

The initial implementation was produced with OpenAI Codex assistance at
Sorbarikor Inene's direction; the committed tests and outputs are independently
reproducible from the source.

## Author and license

Sorbarikor Inene — [@soin8293](https://github.com/soin8293)

MIT License.
