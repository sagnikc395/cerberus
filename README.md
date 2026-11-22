# Cerberus

A central control plane for monitoring AI agents and running guardrail checks on their traffic. Agents send events; the engine evaluates them with pluggable checks, applies per-agent policies, routes risky cases to human review, and reports measured accuracy for every check.

Built in Go on top of [anchora](https://github.com/sagnikc395/anchora).

## What it does

- **Pluggable checks:** every guardrail implements one interface and returns a verdict (score, label, evidence span, latency, cost).
- **Tiered execution:** cheap checks (regex, validators) run first; expensive ones (classifier, LLM judge) run only when needed.
- **Policy layer:** per-agent rules map verdicts to actions (log, alert, redact, quarantine, block). Policies are versioned and can be dry-run against historical traffic.
- **Checkpointed evaluation:** each event is a workflow that fans out checks in parallel, with per-check timeouts, retries, and idempotency keys.
- **Human-in-the-loop:** ambiguous or critical flags wait in a review queue; reviewer labels feed back into the eval set.
- **Eval harness:** precision, recall, and false-positive rate per check and per version, enforced in CI.

## Guardrails

| Category | Checks |
|---|---|
| Input | Prompt injection (direct and indirect), PII in prompts |
| Output | PII and secret leakage, groundedness (sampled) |
| Agent | Tool allowlist, argument bounds, tool call triggered by injected content |
| Cost | Token budget breach, runaway loops, repeated identical tool calls |

## Architecture

```text
Agent or SDK -> HTTP API -> Anchora workflow -> Checks -> Policy -> Evaluation and review
```

Cerberus runs in one Go process. The API starts Anchora workflows directly, or publishes asynchronous reports to JetStream when `NATS_URL` is set. Each event gets one workflow keyed by its event ID. Checks run in parallel within each tier, and a held event gets a review item. In PostgreSQL mode, Anchora checkpoints workflow progress and Cerberus stores evaluations, reviews, and session totals in the same database.

The evaluation and review records mask detected personal data and credentials while preserving byte offsets in text. The workflow input and session history can contain raw traffic. In PostgreSQL mode, protect access to the database and its backups.

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

The types live in `internal/core`. Three optional interfaces adjust how a check is scheduled, and a check that implements none of them still works:

- `AppliesTo(ev Event) bool` - skip events the check cannot fire on, instead of paying for a call that cannot.
- `Configure(params map[string]any) error` - take an agent's allowlist, bounds or thresholds from its policy.
- `RunsIndependently() bool` - run even when the cheap tiers are clean, for a check that samples itself (groundedness). Without it, a check in an expensive tier only ever sees events something else already flagged.

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
    params:
      tools:
        issue_refund:
          required: [order_id, amount]
          args:
            amount: { max: 500, min: 0 }
  - check: injection_indirect
    severity: high
    action: alert
```

The policy is also what configures the checks: `params` on a rule becomes that agent's copy of the detector, and `disabled` turns one off for that agent entirely. The strongest matched action wins, and a check that fires with no rule for it falls back to `default_action` rather than being discarded. The shipped policies are in `policies/`.

Dry run a policy change on past traffic:

```
guardrails policy dry-run --policy policies/candidates/refund-agent.v4.yaml --since 7d
```

A dry run measures the candidate policy's effect on stored verdicts. The output reflects the traffic in your database.

## Evaluation

Each check is evaluated on labeled data and reported per version. A PR that lowers a detector's metrics fails CI: `guardrails eval --enforce` fails when a check is below the floor in `eval/thresholds.yaml`, or more than the tolerance below what the same version scored in `eval/baseline.json`.

| Check | True positives | False positives | False negatives | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| Groundedness (heuristic) | 2 | 0 | 0 | 1.000 | 1.000 | 0.000 |
| Direct injection | 12 | 0 | 3 | 1.000 | 0.800 | 0.000 |
| Indirect injection | 9 | 0 | 1 | 1.000 | 0.900 | 0.000 |
| PII leakage | 4 | 0 | 2 | 1.000 | 0.667 | 0.000 |
| PII in prompts | 6 | 0 | 1 | 1.000 | 0.857 | 0.000 |
| Runaway loop | 2 | 0 | 0 | 1.000 | 1.000 | 0.000 |
| Secret leakage | 7 | 0 | 1 | 1.000 | 0.875 | 0.000 |
| Token budget | 2 | 0 | 0 | 1.000 | 1.000 | 0.000 |
| Tool allowlist | 2 | 0 | 0 | 1.000 | 1.000 | 0.000 |
| Tool argument bounds | 5 | 0 | 0 | 1.000 | 1.000 | 0.000 |
| Tool call from injection | 2 | 0 | 0 | 1.000 | 1.000 | 0.000 |

Measured with `make eval` on 99 hand-written regression cases. The suite includes known misses. The groundedness row covers the heuristic only, with two positive and two negative examples, and is excluded from the CI accuracy gate. The review queue also reports reviewer-confirmed precision as `cerberus_check_reviewer_precision`.

Known failure cases (obfuscation, multilingual, encoding tricks) are documented in [`docs/failure-modes.md`](docs/failure-modes.md).

## Quick start

Requires Go 1.27. Run locally with no infrastructure in one terminal and send the demo traffic from another.

```bash
make run-memory
make demo
```

For durable execution, set `DATABASE_URL` before running `make run`. The bundled Compose stack also provides optional JetStream and telemetry. Copy `.env.example` to `.env` and run `docker compose up -d` to use that stack. Grafana is at `http://localhost:3000`.

### Measured integration results

Local smoke run against Anchora [`5288d5c`](https://github.com/sagnikc395/anchora/commit/5288d5cdeeb647ceef9165b87b5a89c0dc0e37c8) using the heuristic judge.

| Configuration | Demo events evaluated | Demo reviews queued | Concurrent reports stored | Synchronous hold response |
|---|---:|---:|---:|---:|
| In memory | 14 | 3 | 20/20 | 52 ms |
| PostgreSQL 17 | 14 | 3 | 20/20 | 54 ms |
| PostgreSQL 17 and NATS JetStream | 14 | 3 | 20/20 | 54 ms |

Each set of 20 reports used one session and produced 20 distinct turns. Each latency is one local request whose review was still pending when the response arrived. Review expiry was verified with a 2-second timeout in all three configurations.

## Configuration

Cerberus runs in memory with an empty environment. Set a bearer token to enable authentication on the API. Copy the annotated [`.env.example`](.env.example) to get started.

```bash
cp .env.example .env
```

Both `docker compose` and the Makefile read `.env`, so `docker compose up -d` and `make run` pick it up. Make parses the file literally, so write values unquoted with no trailing comments. The Go binaries do not read it themselves - run them through `make`, or `set -a; source .env; set +a` first.

| Variable | Flag | Default | What it does |
|---|---|---|---|
| `CERBERUS_ADDR` | `--addr` | `:8080` | Address the HTTP API listens on |
| `DATABASE_URL` | `--database-url` | _empty_ | Postgres for cerberus's tables and anchora's checkpoints. Empty runs in memory |
| `NATS_URL` | `--nats-url` | _empty_ | NATS with JetStream. Empty submits directly to Anchora |
| `CERBERUS_POLICY_DIR` | `--policies` | `policies` | Directory of policy files, loaded at startup |
| `CERBERUS_TOKEN` | `--token` | _empty_ | Shared bearer token on `/v1`. Empty disables auth |
| `CERBERUS_REVIEW_TIMEOUT` | `--review-timeout` | `24h` | When an undecided queue item is marked expired |
| `CERBERUS_APP_VERSION` | - | `cerberus-dev` | Stamped on every workflow; gates recovery, so set it per build |
| `CERBERUS_URL` | `--url` | `http://localhost:8080` | Control plane the CLI talks to |
| `ANTHROPIC_API_KEY` | - | _empty_ | Enables the LLM judge behind groundedness. Without it the check falls back to its lexical baseline rather than going silent |
| `CERBERUS_JUDGE_MODEL` | - | `claude-opus-5-5` | Judge model |
| `CERBERUS_JUDGE_PRICE_IN` / `_OUT` | - | `4.00` / `20.00` | Per-million-token prices used to attribute cost per verdict. Set both rates when changing the model |
| `POSTGRES_USER` / `_PASSWORD` / `_DB` | - | `cerberus` | Compose only; keep them in step with `DATABASE_URL` |
| `GRAFANA_ADMIN_PASSWORD` | - | `admin` | Compose only. Grafana allows anonymous viewing, so this is for editing |

Flags override environment values. Set `CERBERUS_APP_VERSION` per build so workers recover compatible workflow histories.

## Sending traffic

With the Go SDK:

```go
c := client.New("http://localhost:8080", client.WithToken(os.Getenv("CERBERUS_TOKEN")))

// Fire and forget: the call returns once the control plane has the event.
eventID, err := c.Report(ctx, client.Event{
    AgentID: "refund-agent", SessionID: session, Kind: client.KindCompletion,
    Completion: reply,
})

// Or hold the turn for the verdict, when the agent intends to honour a block.
d, err := c.Check(ctx, client.Event{
    AgentID: "refund-agent", SessionID: session, Kind: client.KindToolCall,
    ToolCall: &client.ToolCall{Name: "issue_refund", Args: map[string]any{"order_id": id, "amount": 900}},
})
if err != nil {
    return err
}
if d.Blocked() {
    return fmt.Errorf("refund held for review: %s", d.ReviewID)
}
```

Or over HTTP directly:

```
POST   /v1/events                     ingest with "wait": true for a synchronous decision
GET    /v1/events?agent=&flagged=&since=7d
GET    /v1/events/{id}
GET    /v1/reviews?state=pending
POST   /v1/reviews/{id}/decision      reviewer state and per-check labels
GET    /v1/policies, /v1/policies/{agent}
GET    /v1/checks?agent=              what an agent actually runs
GET    /v1/stats/precision            reviewer-confirmed precision per check
GET    /healthz, /readyz, /metrics
```

An event can carry a client-chosen `id`. Without one, the API hashes the submitted event before assigning a missing timestamp. Use a unique explicit ID for each distinct occurrence of identical traffic and reuse it on retries. Existing records remain available under their original IDs. Retries of pre-upgrade events can use the original returned ID.

## Review loop

```
guardrails review list
guardrails review decide review:ev-123 --state rejected --reviewer you \
    --label pii_leak@1.0.0=true_positive
```

A synchronous request returns a hold decision and review ID as soon as the review item exists. The workflow waits for a reviewer and marks undecided items expired after `--review-timeout`. The original policy action remains in the outcome. Labels on a decision are what close the loop: they drive the reviewer-precision gauge and are the raw material for the eval set.

## CLI

```
guardrails policy validate [dir]       parse every policy and build the plan it produces
guardrails policy show <agent>         the policy as loaded, and the checks that agent runs
guardrails policy dry-run --policy FILE [--since 7d]
guardrails eval [--format text|md|json] [--enforce] [--update-baseline]
guardrails checks [--agent NAME]
guardrails review list | decide
guardrails demo
```

## Repository layout

```
cmd/cerberus            the control plane: ingest, workers, review API, metrics
cmd/guardrails          operator CLI
client/                 Go SDK for agents
internal/core           Event, Verdict, Check, the registry
internal/checks/        one package per guardrail family
internal/policy         rules, versions, evaluation, dry-run replay
internal/engine         the anchora workflow and the tiered executor
internal/store          Postgres and in-memory stores
internal/broker         optional NATS JetStream ingress
internal/redact         length-preserving redaction
internal/eval           the harness, thresholds and baseline comparison
internal/api            HTTP surface
policies/               shipped policies; candidates/ holds unactivated versions
eval/datasets/          labeled cases, including known-gaps.jsonl
deploy/                 prometheus scrape config, grafana datasource and dashboard
.env.example            every environment variable, annotated
```

## Scope

In: check framework, PII, injection, one tool-call policy, review loop, eval harness.

Out for now: multi-tenant auth, production-scale load claims, hallucination accuracy guarantees. `/v1` is protected by a single shared bearer token (`CERBERUS_TOKEN`); any caller holding it can read every agent's traffic.

The classifier tier exists in the interface and is unoccupied: there is no local model yet, which is the largest gap between what this detects and what it should.

## Observability

The platform exports its own health: Prometheus metrics (queue lag, check latency, failure rate) and OpenTelemetry traces per evaluated event, emitted by anchora for every workflow and live step.

```
cerberus_events_received_total{agent,kind}
cerberus_events_evaluated_total{agent,action}
cerberus_check_latency_seconds{check,version,tier}
cerberus_check_verdicts_total{check,version,label}
cerberus_check_errors_total / cerberus_checks_skipped_total / cerberus_tier_runs_total
cerberus_check_cost_usd_total{check,version}
cerberus_policy_actions_total{agent,policy_version,action,severity}
cerberus_violations_total{agent,check,action}
cerberus_check_reviewer_precision{check,version}
cerberus_review_queue_depth{agent} / cerberus_broker_lag_seconds / cerberus_broker_depth
cerberus_redactions_total
cerberus_evaluation_seconds{agent}
```

## Development

```
make test          unit and integration tests, including the durable review wait
make test-race     the same under the race detector
make ci            formatting, vet, tests, policy validation, the accuracy gate
make eval-report   write the markdown accuracy table to eval/report.md
```

The integration tests run the real Anchora engine and Cerberus API in memory. They cover workflow completion, review handling, and event deduplication.
