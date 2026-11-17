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
| Cost | Token budget breach, runaway loops, repeated identical tool calls |

PII is redacted before anything is persisted. Redaction is length-preserving, so the evidence spans a check produced still point at the right text in the stored record.

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

One event is one anchora workflow. The checks fan out as parallel checkpointed steps, the policy decision and the store write are steps of their own, and the review queue is a durable wait: a process that dies mid-evaluation resumes from its last checkpoint instead of re-running the work, and a redelivered event joins the existing execution rather than starting a second one.

Postgres holds both the engine's checkpoints and cerberus's own tables (`cerberus.evaluations`, `cerberus.reviews`, `cerberus.sessions`), so a deployment runs one database.

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

- `AppliesTo(ev Event) bool` — skip events the check cannot fire on, instead of paying for a call that cannot.
- `Configure(params map[string]any) error` — take an agent's allowlist, bounds or thresholds from its policy.
- `RunsIndependently() bool` — run even when the cheap tiers are clean, for a check that samples itself (groundedness). Without it, a check in an expensive tier only ever sees events something else already flagged.

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

```
refund-agent: v3 -> v4 over 168h0m0s of traffic (13 events)

ACTION                     BEFORE    AFTER    DELTA
alert                           3        1       -2
allow                           4        4       +0
block                           2        2       +0
quarantine                      2        4       +2
redact                          1        1       +0
require_human_approval          1        1       +0

2 events change action: 2 newly held, 0 newly released, 2 newly queued for review
```

A dry run replays the stored verdicts, so the diff is the policy's effect alone and not detector drift.

## Evaluation

Each check is evaluated on labeled data and reported per version. A PR that lowers a detector's metrics fails CI: `guardrails eval --enforce` fails when a check is below the floor in `eval/thresholds.yaml`, or more than the tolerance below what the same version scored in `eval/baseline.json`.

| Check | Cases | Precision | Recall | FPR |
|---|---|---|---|---|
| PII in prompts (regex + validators) | 7 pos / 53 neg | 1.00 | 0.86 | 0.00 |
| PII leakage | 6 pos / 41 neg | 1.00 | 0.67 | 0.00 |
| Secret leakage | 8 pos / 39 neg | 1.00 | 0.88 | 0.00 |
| Injection (direct) | 15 pos / 24 neg | 1.00 | 0.80 | 0.00 |
| Injection (indirect) | 10 pos / 7 neg | 1.00 | 0.90 | 0.00 |
| Tool allowlist | 2 pos / 17 neg | 1.00 | 1.00 | 0.00 |
| Tool argument bounds | 5 pos / 14 neg | 1.00 | 1.00 | 0.00 |
| Tool call from injection | 2 pos / 2 neg | 1.00 | 1.00 | 0.00 |
| Token budget | 2 pos / 97 neg | 1.00 | 1.00 | 0.00 |
| Runaway loop | 2 pos / 97 neg | 1.00 | 1.00 | 0.00 |
| Groundedness 🚧 | 2 pos / 2 neg | not enforced | | |

Measured by `make eval` over the 99 cases in `eval/datasets`, which includes `known-gaps.jsonl`: a corpus of obfuscation and multilingual attacks that the detectors are known to miss, which is where the missing recall is. These are hand-written regression sets, not published attack corpora, so the numbers say that a change did not break a detector and nothing about performance against an adversary who has read the code. Groundedness is reported and never enforced: its judge has not been measured on a labeled set.

The one source of production signal is the review queue. Every reviewer decision labels the checks that fired, and `cerberus_check_reviewer_precision` reports the share each check version got confirmed.

Known failure cases (obfuscation, multilingual, encoding tricks) are documented in [`docs/failure-modes.md`](docs/failure-modes.md).

## Quick start

```bash
docker compose up -d      # broker, postgres, prometheus, grafana
make run                  # engine + workers
make demo                 # sends sample agent traffic, including risky tool calls
```

```
SCENARIO                               ACTION                   SEVERITY   CHECKS THAT FIRED
benign refund question                 allow                               []
card number in the prompt              redact                   medium     [pii_prompt(0.99)]
order id that is not a card            allow                               []
direct prompt injection                alert                    medium     [injection_direct(0.80)]
pii leaking into the reply             quarantine               critical   [pii_leak(0.99)]
credential in the reply                block                    critical   [secret_leak(0.95)]
refund above the declared bound        require_human_approval   high       [tool_call_bounds(0.90)]
tool the agent may not call            block                    high       [tool_allowlist(0.95)]
indirect injection in a retrieved page quarantine               critical   [tool_call_from_injection(0.95) ...]
ungrounded answer                      alert                    low        [groundedness(0.89)]
identical tool call 3/4                alert                    low        [runaway_loop(0.50)]
```

Dashboard: `http://localhost:3000` (violations by check, per-check precision from reviewer decisions, review queue).

`make run-memory` runs the whole control plane with an in-process broker and an in-memory store, with no infrastructure at all. Nothing survives a restart, which is why it is for demos and tests.

## Configuration

Everything is configured by environment variable or flag, and nothing is required: with an empty environment the control plane runs in memory with no broker and no auth. Copy the annotated [`.env.example`](.env.example) to get started.

```bash
cp .env.example .env
```

Both `docker compose` and the Makefile read `.env`, so `docker compose up -d` and `make run` pick it up. Make parses the file literally, so write values unquoted with no trailing comments. The Go binaries do not read it themselves — run them through `make`, or `set -a; source .env; set +a` first.

| Variable | Flag | Default | What it does |
|---|---|---|---|
| `CERBERUS_ADDR` | `--addr` | `:8080` | Address the HTTP API listens on |
| `DATABASE_URL` | `--database-url` | _empty_ | Postgres for cerberus's tables and anchora's checkpoints. Empty runs in memory, with no durability |
| `NATS_URL` | `--nats-url` | _empty_ | NATS with JetStream. Empty uses the in-process broker |
| `CERBERUS_POLICY_DIR` | `--policies` | `policies` | Directory of policy files, loaded at startup |
| `CERBERUS_TOKEN` | `--token` | _empty_ | Shared bearer token on `/v1`. Empty disables auth |
| `CERBERUS_REVIEW_TIMEOUT` | `--review-timeout` | `24h` | When an undecided queue item is marked expired |
| `CERBERUS_APP_VERSION` | — | `cerberus-dev` | Stamped on every workflow; gates recovery, so set it per build |
| `CERBERUS_URL` | `--url` | `http://localhost:8080` | Control plane the CLI talks to |
| `ANTHROPIC_API_KEY` | — | _empty_ | Enables the LLM judge behind groundedness. Without it the check falls back to its lexical baseline rather than going silent |
| `CERBERUS_JUDGE_MODEL` | — | `claude-opus-5-5` | Judge model |
| `CERBERUS_JUDGE_PRICE_IN` / `_OUT` | — | `4.00` / `20.00` | Per-million-token prices used to attribute cost per verdict. Change them with the model, or the spend panel will lie |
| `POSTGRES_USER` / `_PASSWORD` / `_DB` | — | `cerberus` | Compose only; keep them in step with `DATABASE_URL` |
| `GRAFANA_ADMIN_PASSWORD` | — | `admin` | Compose only. Grafana allows anonymous viewing, so this is for editing |

A flag always beats the environment. `CERBERUS_APP_VERSION` is worth setting in a real deployment: an executor only recovers workflows it can run, so two builds with different check code must not claim each other's in-flight evaluations.

## Sending traffic

With the Go SDK:

```go
c := client.New("http://localhost:8080", client.WithToken(os.Getenv("CERBERUS_TOKEN")))

// Fire and forget: the call returns once the control plane has the event.
id, err := c.Report(ctx, client.Event{
    AgentID: "refund-agent", SessionID: session, Kind: client.KindCompletion,
    Completion: reply,
})

// Or hold the turn for the verdict, when the agent intends to honour a block.
d, err := c.Check(ctx, client.Event{
    AgentID: "refund-agent", SessionID: session, Kind: client.KindToolCall,
    ToolCall: &client.ToolCall{Name: "issue_refund", Args: map[string]any{"order_id": id, "amount": 900}},
})
if d.Blocked() {
    return fmt.Errorf("refund held for review: %s", d.ReviewID)
}
```

Or over HTTP directly:

```
POST   /v1/events                     ingest, ?wait for the synchronous verdict
GET    /v1/events?agent=&flagged=&since=7d
GET    /v1/events/{id}
GET    /v1/reviews?state=pending
POST   /v1/reviews/{id}/decision      reviewer state and per-check labels
GET    /v1/policies, /v1/policies/{agent}
GET    /v1/checks?agent=              what an agent actually runs
GET    /v1/stats/precision            reviewer-confirmed precision per check
GET    /healthz, /readyz, /metrics
```

An event may carry a client-chosen id; without one the control plane derives it from the content, so a retry after a timeout does not produce a second evaluation.

## Review loop

```
guardrails review list
guardrails review decide review:ev-123 --state rejected --reviewer you \
    --label pii_leak@1.0.0=true_positive
```

An event whose action is `require_human_approval` or `quarantine` parks in the queue and the workflow waits on it. A decision resumes the workflow; nothing within `--review-timeout` marks the item expired and the policy's action stands. Labels on a decision are what close the loop: they drive the reviewer-precision gauge and are the raw material for the eval set.

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
internal/broker         NATS JetStream and in-process brokers
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

The integration tests run the real engine against the in-memory store and anchora's memory store, so the workflow, the review wait state and the idempotency guarantees are exercised without any infrastructure.
