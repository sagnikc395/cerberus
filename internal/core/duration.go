package core

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDuration accepts Go durations plus the day and week suffixes an
// operator reaches for on the command line: "7d", "2w", "36h".
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	unit := s[len(s)-1]
	if unit != 'd' && unit != 'w' {
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: want 30m, 24h, 7d or 2w", s)
		}
		return d, nil
	}
	n, err := strconv.ParseFloat(s[:len(s)-1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: want 30m, 24h, 7d or 2w", s)
	}
	scale := 24 * time.Hour
	if unit == 'w' {
		scale = 7 * 24 * time.Hour
	}
	return time.Duration(n * float64(scale)), nil
}
