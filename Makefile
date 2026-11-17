# cerberus development targets.
#
# The infrastructure runs in compose; the engine runs on the host, so what you
# are editing is what the dashboard is measuring.

# .env, when present, is the source of truth for both compose and these
# targets. Values are parsed literally: unquoted, no trailing comments.
ifneq (,$(wildcard .env))
include .env
export
endif

DATABASE_URL ?= postgres://cerberus:cerberus@localhost:5432/cerberus?sslmode=disable
NATS_URL     ?= nats://localhost:4222
CERBERUS_URL ?= http://localhost:8080
GO           ?= go

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: up
up: ## start the broker, database, prometheus and grafana
	docker compose up -d
	@echo "grafana: http://localhost:3000   prometheus: http://localhost:9090"

.PHONY: down
down: ## stop the infrastructure (volumes are kept)
	docker compose down

.PHONY: clean-infra
clean-infra: ## stop the infrastructure and delete its data
	docker compose down -v

.PHONY: run
run: ## run the engine and workers against the compose infrastructure
	DATABASE_URL="$(DATABASE_URL)" NATS_URL="$(NATS_URL)" $(GO) run ./cmd/cerberus

.PHONY: run-memory
run-memory: ## run with no infrastructure at all: in-memory store and broker
	$(GO) run ./cmd/cerberus

.PHONY: demo
demo: ## send sample agent traffic, including risky tool calls
	$(GO) run ./cmd/guardrails demo --url "$(CERBERUS_URL)"

.PHONY: build
build: ## build both binaries into ./bin
	mkdir -p bin
	$(GO) build -o bin/cerberus ./cmd/cerberus
	$(GO) build -o bin/guardrails ./cmd/guardrails

.PHONY: test
test: ## run the unit and integration tests
	$(GO) test ./...

.PHONY: test-race
test-race: ## run the tests under the race detector
	$(GO) test -race ./...

.PHONY: vet
vet: ## run go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## format every Go file
	gofmt -w $(shell find . -name '*.go' -not -path './bin/*')

.PHONY: fmt-check
fmt-check: ## fail when something is unformatted
	@unformatted=$$(gofmt -l $$(find . -name '*.go' -not -path './bin/*')); \
	if [ -n "$$unformatted" ]; then echo "unformatted:"; echo "$$unformatted"; exit 1; fi

.PHONY: policy-validate
policy-validate: ## parse every policy and build the plan it produces
	$(GO) run ./cmd/guardrails policy validate policies
	$(GO) run ./cmd/guardrails policy validate policies/candidates

.PHONY: eval
eval: ## measure every check on the labeled data
	$(GO) run ./cmd/guardrails eval

.PHONY: eval-enforce
eval-enforce: ## the CI gate: fail when a check is below its threshold or baseline
	$(GO) run ./cmd/guardrails eval --enforce

.PHONY: eval-report
eval-report: ## write the markdown accuracy table to eval/report.md
	$(GO) run ./cmd/guardrails eval --format md --out eval/report.md
	@echo "wrote eval/report.md"

.PHONY: eval-baseline
eval-baseline: ## record the current numbers as the baseline CI compares against
	$(GO) run ./cmd/guardrails eval --update-baseline

.PHONY: dry-run
dry-run: ## replay the candidate policy over the last week of stored traffic
	DATABASE_URL="$(DATABASE_URL)" $(GO) run ./cmd/guardrails policy dry-run \
		--policy policies/candidates/refund-agent.v4.yaml --since 7d

.PHONY: ci
ci: fmt-check vet test policy-validate eval-enforce ## everything CI runs
