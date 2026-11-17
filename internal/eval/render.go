package eval

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Markdown renders the table the README shows and CI comments with.
func (r Report) Markdown(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "## Check accuracy\n\n")
	fmt.Fprintf(&b, "%d cases across %s, run at %s.\n\n", r.Cases,
		strings.Join(r.Datasets, ", "), r.RanAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "| Check | Version | Dataset | Precision | Recall | FPR | TP | FP | FN | p95 |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|---|---|\n")
	for _, m := range r.Checks {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %d | %d | %d | %s |\n",
			m.Check, m.Version, m.Dataset,
			ratio(m.Precision, m.TruePositives+m.FalsePositives),
			ratio(m.Recall, m.TruePositives+m.FalseNegatives),
			ratio(m.FPR, m.FalsePositives+m.TrueNegatives),
			m.TruePositives, m.FalsePositives, m.FalseNegatives,
			m.LatencyP95.Round(time.Microsecond))
	}
	b.WriteString("\n")
	for _, m := range r.Checks {
		if len(m.Misses) == 0 && len(m.FalseAlarms) == 0 {
			continue
		}
		fmt.Fprintf(&b, "- **%s@%s** (%s):", m.Check, m.Version, m.Dataset)
		if len(m.Misses) > 0 {
			fmt.Fprintf(&b, " missed `%s`", strings.Join(m.Misses, "`, `"))
		}
		if len(m.FalseAlarms) > 0 {
			fmt.Fprintf(&b, " false alarm on `%s`", strings.Join(m.FalseAlarms, "`, `"))
		}
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Text renders the compact form the CLI prints.
func (r Report) Text(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%-28s %-10s %9s %9s %9s %7s %7s %7s\n", "CHECK", "VERSION", "PRECISION", "RECALL", "FPR", "TP", "FP", "FN")
	for _, m := range r.Overall() {
		fmt.Fprintf(&b, "%-28s %-10s %9s %9s %9s %7d %7d %7d\n",
			m.Check, m.Version,
			ratio(m.Precision, m.TruePositives+m.FalsePositives),
			ratio(m.Recall, m.TruePositives+m.FalseNegatives),
			ratio(m.FPR, m.FalsePositives+m.TrueNegatives),
			m.TruePositives, m.FalsePositives, m.FalseNegatives)
	}
	fmt.Fprintf(&b, "\n%d cases, datasets: %s\n", r.Cases, strings.Join(r.Datasets, ", "))
	_, err := io.WriteString(w, b.String())
	return err
}

// ratio prints a metric, or "n/a" when its denominator was zero. A check with
// no positive cases has no recall, and printing 0.000 would read as a failure
// rather than as missing data.
func ratio(value float64, denominator int) string {
	if denominator == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", value)
}
