## cereberus

A central control plane for monitoring AI agents and running guardrail checks on their traffic. Agents send events; the engine evaluates them with pluggable checks, applies per-agent policies, routes risky cases to human review, and reports measured accuracy for every check.

Built in Go on top of [anchora](https://github.com/sagnikc395/anchora).

## What it does

- **Pluggable checks:** every guardrail implements one interface and returns a verdict (score, label, evidence span, latency, cost).
- **Tiered execution:** cheap checks (regex, validators) run first; expensive ones (classifier, LLM judge) run only when needed.
- **Policy layer:** per-agent rules map verdicts to actions (log, alert, redact, quarantine, block). Policies are versioned and can be dry-run against historical traffic.
- **Durable evaluation:** each event is a workflow that fans out checks in parallel, with per-check timeouts, retries, and idempotency keys.
- **Human-in-the-loop:** ambiguous or critical flags wait in a review queue; reviewer labels feed back into the eval set.
- **Eval harness:** precision, recall, and false-positive rate per check and per version, enforced in CI.

## Guardrails

| Category | Checks |
|---|---|
| Input | Prompt injection (direct and indirect), PII in prompts |
| Output | PII and secret leakage, groundedness (sampled) 🚧 |
| Agent | Tool allowlist, argument bounds, tool call triggered by injected content |
| Cost | Token budget breach, runaway loops, repeated identical tool calls 🚧 |

PII is redacted before anything is persisted.

## Architecture

```
agent / SDK ──► event ──► broker (NATS JetStream) ──► workflow engine
                                                         │
                          ┌──────────────┬───────────────┼───────────────┐
                          ▼              ▼               ▼               ▼
                      PII check    Injection check   Tool-call check   Groundedness
                          └──────────────┴───────┬───────┴───────────────┘
                                                 ▼
                                        policy evaluation
                                                 │
                         ┌───────────────┬───────┴────────┐
                         ▼               ▼                ▼
                    store + metrics   alert        review queue (wait state)
```

## The check interface

```go
type Check interface {
    Name() string
    Version() string
    Tier() Tier // Regex | Classifier | LLMJudge
    Run(ctx context.Context, ev Event) (Verdict, error)
}

type Verdict struct {
    Label    string  // e.g. "pii_leak", "injection", "ok"
    Score    float64 // 0..1
    Evidence []Span  // exact text spans that triggered the label
    Latency  time.Duration
    CostUSD  float64
}
```

Checks register by name and version, so a new detector can be run side by side with the old one on the same traffic.

## Policy example

```yaml
agent: refund-agent
version: 3
rules:
  - check: pii_leak
    severity: critical
    action: quarantine
  - check: tool_call_bounds
    when: { tool: issue_refund, amount_gt: 500 }
    action: require_human_approval
  - check: injection_indirect
    severity: high
    action: alert
```

Dry run a policy change on past traffic:

```
guardrails policy dry-run --policy refund-agent.v4.yaml --since 7d
```

## Evaluation

Each check is evaluated on labeled data and reported per version. A PR that lowers a detector's metrics fails CI.

| Check | Dataset | Precision | Recall | FPR |
|---|---|---|---|---|
| PII (regex + validators) | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| Injection | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| Indirect injection | _TBD_ | _TBD_ | _TBD_ | _TBD_ |

Known failure cases (obfuscation, multilingual, encoding tricks) are documented in `docs/failure-modes.md`.

## Quick start

```bash
docker compose up -d      # broker, postgres, prometheus, grafana
make run                  # engine + workers
make demo                 # sends sample agent traffic, including risky tool calls
```

Dashboard: `http://localhost:3000` (violations by check, per-check precision from reviewer decisions, review queue).

## Scope

In: check framework, PII, injection, one tool-call policy, review loop, eval harness.

Out for now: multi-tenant auth, production-scale load claims, hallucination accuracy guarantees.

## Observability

The platform exports its own health: Prometheus metrics (queue lag, check latency, failure rate) and OpenTelemetry traces per evaluated event.
