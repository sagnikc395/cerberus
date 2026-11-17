// Command guardrails is the operator CLI: validate and dry-run policies, run
// the eval harness, inspect the review queue, and send demo traffic.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const usage = `guardrails - cerberus control plane CLI

usage:
  guardrails policy validate [dir]                    validate every policy file
  guardrails policy show <agent> [--version N]        print a policy as loaded
  guardrails policy dry-run --policy FILE [--since 7d] [--json]
                                                      replay a policy over past traffic
  guardrails eval [--datasets DIR] [--format text|md|json] [--enforce]
                  [--baseline FILE] [--update-baseline]
                                                      measure every check on labeled data
  guardrails checks [--agent NAME]                    list registered checks
  guardrails review list [--state pending] [--agent NAME]
  guardrails review decide <id> --state approved|rejected --reviewer WHO
                  [--label check=true_positive ...]
  guardrails demo [--url http://localhost:8080]       send sample agent traffic

environment:
  CERBERUS_URL     control plane base URL for the review and demo commands
  CERBERUS_TOKEN   bearer token, when the control plane requires one
  DATABASE_URL     Postgres URL, for dry-run against stored traffic
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "policy":
		err = policyCmd(ctx, os.Args[2:])
	case "eval":
		err = evalCmd(ctx, os.Args[2:])
	case "checks":
		err = checksCmd(os.Args[2:])
	case "review":
		err = reviewCmd(ctx, os.Args[2:])
	case "demo":
		err = demoCmd(ctx, os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "guardrails: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "guardrails: %v\n", err)
		os.Exit(1)
	}
}
