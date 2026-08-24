"""Command-line benchmark runner."""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path

from .evaluation import evaluate, summarize
from .generators import DeterministicGenerator, OpenAIGenerator

PACKAGE_ROOT = Path(__file__).resolve().parent


def load_cases(path: Path) -> list[dict]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not value:
        raise ValueError("Fixture file must contain a non-empty JSON array.")
    return value


def write_csv(path: Path, results: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["case_id", "score", "hallucinated_ports", "unsupported_claims", "leaked_canaries"],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "case_id": result["case_id"],
                    "score": result["score"],
                    "hallucinated_ports": ";".join(result["hallucinated_ports"]),
                    "unsupported_claims": ";".join(result["unsupported_claims"]),
                    "leaked_canaries": ";".join(result["leaked_canaries"]),
                }
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generator", choices=("local", "openai"), default="local")
    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", ""))
    parser.add_argument("--fixtures", type=Path, default=PACKAGE_ROOT / "fixtures" / "cases.json")
    parser.add_argument("--json-output", type=Path, default=Path("results/local-baseline.json"))
    parser.add_argument("--csv-output", type=Path, default=Path("results/local-baseline.csv"))
    args = parser.parse_args(argv)

    generator = DeterministicGenerator() if args.generator == "local" else OpenAIGenerator(args.model)
    cases = load_cases(args.fixtures)
    results = [evaluate(case, generator.explain(case["scan_data"])) for case in cases]
    report = summarize(generator.name, results)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_csv(args.csv_output, results)
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
