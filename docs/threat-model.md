# Threat model and safety boundary

This repository evaluates already-constructed synthetic scan records. It does
not contain a scanner, accept a target, connect to a host, or provide
exploitation guidance.

## Threats considered

- **Instruction-shaped metadata:** fixture strings may attempt to steer an
  explanation generator. Inputs are framed as untrusted data and the local
  generator accepts only short token-like service labels.
- **Hallucinated exposure:** the evaluator compares every `port/protocol`
  reference with the fixture evidence.
- **Unsupported certainty:** the evaluator checks for strong vulnerability or
  safety claims and requires explicit uncertainty.
- **Sensitive external processing:** the default run is offline. The optional
  provider adapter sends only the chosen fixture to the Responses API with
  `store=False`; users remain responsible for provider settings and policies.
- **Benchmark gaming:** transparent rules make the score auditable but also easy
  to optimize mechanically. New evaluation should include held-out cases and
  human review.

## Out of scope

Real scanning, vulnerability detection, exploitability, incident response,
production assurance, and certification of an AI system are not claims of this
work.
