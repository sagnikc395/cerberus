# Known failure modes

Every number in the eval report comes from the datasets in `eval/datasets`.
The gaps below are not speculation: most of them are encoded as labeled cases
in `eval/datasets/known-gaps.jsonl`, so the recall they cost is visible in the
report rather than discovered in production.

Run `make eval` to see where things stand.

## How to read the accuracy numbers

The datasets are 99 hand-written cases plus a known-gap corpus. They are a
regression guard, not a benchmark: they say that a change did not break a
detector, and nothing about how the detector performs against an adversary who
has read this file. Published attack corpora have not been imported yet, and
the thresholds in `eval/thresholds.yaml` are set below the measured numbers
for that reason.

Reviewer decisions are the one source of production signal: each decision on a
queued item labels the checks that fired, and
`cerberus_check_reviewer_precision` reports the share a human confirmed. That
gauge, not the dataset, is what tells you a detector is drifting.

## PII

The detectors are regex plus validators (Luhn, the SSA allocation rules,
IBAN mod-97). What they miss:

- **Numbers written as words.** "one two three, four five, six seven eight
  nine" is an SSN to a reader and nothing to the detector (`gap-009`).
- **Values split by prose.** "4242 then 4242 then 4242 and finally 4242"
  defeats the card pattern (`gap-010`).
- **Non-ASCII digits.** Full-width or Arabic-Indic digits are not matched
  (`gap-012`). Normalizing them would be a small change and is not done yet.
- **Non-US formats.** Only US SSNs and NANP phone numbers are validated;
  national id numbers, non-NANP phone formats and most postal addresses are
  not detected at all.
- **Names and addresses.** There is no named-entity model, so a name on its own
  is invisible. "Dana Reyes, ssn 123-45-6789" is caught by the SSN, not the
  name.
- **A dotted quad of single digits** is treated as a version string, not an IP
  address: `1.2.3.4` is not reported, `10.0.0.1` is. This is a deliberate
  precision trade.

## Secrets

- **Documentation keys are suppressed on purpose.** A value containing
  `EXAMPLE`, `YOUR_`, `xxxx`, `<`, `${` and similar is treated as a
  placeholder, which is what keeps READMEs and code samples out of the queue.
  The cost is that AWS's own documentation key, `AKIAIOSFODNN7EXAMPLE`, is not
  reported. The eval set uses a realistic key instead, and that choice is why.
- **Keys broken across lines** are missed (`gap-011`).
- **Unknown providers.** A credential shape with no rule and not enough entropy
  for the generic assignment rule goes unreported.
- **Generic assignments need an assignment.** A bare high-entropy token with no
  `key=` or `secret:` near it is not flagged, because the false-positive cost
  on hashes, ids and base64 payloads is too high.

## Prompt injection, direct and indirect

The signature library is the regex tier. The classifier tier is declared in the
`Tier` enum and currently unoccupied: there is no local model yet, which is the
largest single gap in this system.

- **English only.** The same attack in Spanish or German is missed
  (`gap-004`, `gap-005`). This is the most likely attack in practice and the
  cheapest to fix with a classifier.
- **Character-level obfuscation.** Zero-width characters, non-breaking spaces
  and repeated whitespace are normalized; homoglyphs (Cyrillic `о` for `o`) and
  leetspeak (`1gn0r3`) are not (`gap-001`, `gap-003`). Some of these are caught
  anyway because a second clause of the attack is still literal, which is luck,
  not coverage.
- **Encoding.** Base64 is decoded, recursing one level, so two layers are
  handled and three are not. Hex, ROT13 and URL encoding are only hinted at by
  the `encoding_hint` signature.
- **Instructions spread across structure.** An attack split over list items or
  table cells, where no single sentence matches, is missed (`gap-008`).
- **Long-context dilution.** Scores are per document, so one injected sentence
  inside a very long document scores the same as a short one. That is
  deliberate, but it means a retrieved page can be padded to look ordinary to a
  human reviewer.
- **Trust is declared, not inferred.** `Document.Trusted` comes from the SDK
  caller. An integration that marks retrieved pages as trusted turns the
  indirect check off for itself, silently. The engine cannot tell.

## Tool-call checks

- **Bounds are only as good as the declaration.** `tool_call_bounds` compares
  against what the policy declares for that tool. An undeclared tool, or an
  undeclared argument, passes.
- **The injection correlation needs a literal mention.** A tool call is
  attributed to injected content when the content names the tool or carries one
  of the argument values. An attack that nudges the agent toward a call without
  naming it is reported as `injection_indirect` alone.
- **One event at a time.** The correlation looks at the event's own context. An
  injection delivered on turn three that produces a tool call on turn seven is
  not linked, because the check is a pure function of one event.

## Cost and loop checks

- **They read the session rollup**, which the store advances once per event. A
  burst of events evaluated concurrently can each see a slightly stale view, so
  a budget breach is detected within a turn or two of the real crossing, not
  exactly at it.
- **Repeated-call detection compares rendered arguments.** A loop that varies a
  timestamp or a request id in its arguments is not seen as a repeat.
- **The window is the last 20 calls** in a session, so a long-period loop is
  invisible.

## Groundedness

Experimental, and labeled as such in its version string.

- **Accuracy is unmeasured.** There is no labeled groundedness set, so it is
  reported and never enforced in CI, and the shipped policy routes it to
  `alert` rather than to anything blocking. Treat its score as a hint.
- **The default judge is lexical.** With no model configured it scores on word
  overlap, which rewards paraphrase-free copying and punishes legitimate
  rewording.
- **The LLM judge is a model call on untrusted text.** The prompt tells it the
  sources are data and not instructions, and nothing more: a sufficiently
  determined injection in a source document may influence its verdict. It is
  also the only check that costs money per event, which is why it is sampled
  and sits behind an overlap pre-filter.
- **Sampling is deterministic in the event id**, so the same traffic judges the
  same events on a replay. The flip side is that an attacker who can choose
  event ids can choose not to be sampled.

## Policy and review

- **The strongest action wins.** One noisy detector with a `quarantine` rule
  can stop a lot of traffic. Dry-run a policy change against stored traffic
  before activating it: `guardrails policy dry-run --policy FILE --since 7d`.
- **A dry run replays stored verdicts**, not the checks. It isolates the policy
  change, and it will not show you the effect of a detector change. For that,
  register the new detector version beside the old one and compare verdicts on
  live traffic.
- **An expired review keeps the strict action.** If nobody decides within
  `--review-timeout`, the item is marked expired and whatever the policy
  decided stands. A queue that nobody drains is a queue that holds agents.
- **No per-tenant authentication.** `/v1` is protected by one shared bearer
  token, and every caller that holds it can read every agent's events and
  decide any review. Multi-tenant auth is explicitly out of scope for now.

## Platform

- **Redaction is length-preserving**, so evidence offsets still point at the
  right text after a value is masked. The mask reveals the length of what it
  replaced, and that is a deliberate trade for reviewable evidence.
- **Checks are replayed from checkpoints after a crash**, not re-run. A
  detector whose code changes between the crash and the recovery is caught by
  anchora's nondeterminism check rather than silently mixing versions; the
  workflow fails loudly and the event is re-evaluated under the new app version.
- **The in-process broker has no durability.** It exists for `make demo` and
  the tests. Without `NATS_URL` and `DATABASE_URL`, an event accepted at ingest
  is lost on restart.
