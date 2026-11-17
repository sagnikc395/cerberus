// Package pii detects personal data in text. The detectors are shared by the
// PII guardrail checks and by the redactor that runs before anything is
// persisted, so what a reviewer sees and what is stored agree on the spans.
package pii

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Type names a class of personal data.
type Type string

const (
	Email      Type = "email"
	Phone      Type = "phone"
	SSN        Type = "ssn"
	CreditCard Type = "credit_card"
	IBAN       Type = "iban"
	IPAddress  Type = "ip_address"
	DOB        Type = "date_of_birth"
)

// Match is one detection in a piece of text.
type Match struct {
	Type  Type
	Start int
	End   int
	Value string
	// Validated is true when a checksum or range rule confirmed the match
	// rather than the pattern alone. Unvalidated matches score lower.
	Validated bool
}

// Severity weights the match for scoring. Account identifiers outrank contact
// details, which outrank network addresses.
func (m Match) Severity() float64 {
	switch m.Type {
	case CreditCard, SSN, IBAN:
		return 1.0
	case Email, Phone, DOB:
		return 0.7
	case IPAddress:
		return 0.4
	}
	return 0.5
}

type detector struct {
	typ      Type
	re       *regexp.Regexp
	validate func(string) bool
}

var (
	emailRe = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	// Separators are optional and mixed on purpose: agents paste numbers in
	// whatever shape the user typed them.
	ccRe    = regexp.MustCompile(`\b(?:\d[ \-]?){12,18}\d\b`)
	ssnRe   = regexp.MustCompile(`\b(\d{3})[\- ]?(\d{2})[\- ]?(\d{4})\b`)
	phoneRe = regexp.MustCompile(`(?:\+1[ \-.]?)?\(?\b([2-9]\d{2})\)?[ \-.]?([2-9]\d{2})[ \-.]?(\d{4})\b`)
	ibanRe  = regexp.MustCompile(`\b([A-Z]{2})(\d{2})([A-Z0-9]{11,30})\b`)
	ipRe    = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	dobRe   = regexp.MustCompile(`(?i)\b(?:dob|date of birth|born)\b[^0-9]{0,12}(\d{1,4}[\-/.]\d{1,2}[\-/.]\d{1,4})`)
)

var detectors = []detector{
	{typ: Email, re: emailRe, validate: func(string) bool { return true }},
	{typ: CreditCard, re: ccRe, validate: luhn},
	{typ: SSN, re: ssnRe, validate: validSSN},
	{typ: IBAN, re: ibanRe, validate: validIBAN},
	{typ: Phone, re: phoneRe, validate: func(string) bool { return true }},
	{typ: IPAddress, re: ipRe, validate: validIPv4},
	{typ: DOB, re: dobRe, validate: func(string) bool { return true }},
}

// Scan returns every match in text, ordered by position, with overlaps
// resolved in favour of the higher-severity type. A bare 16-digit number is
// only reported as a card when it passes Luhn, which is what keeps the
// false-positive rate on order ids and invoice numbers low.
func Scan(text string) []Match {
	if text == "" {
		return nil
	}
	var all []Match
	for _, d := range detectors {
		for _, loc := range d.re.FindAllStringIndex(text, -1) {
			raw := text[loc[0]:loc[1]]
			if !plausible(d.typ, text, loc[0], loc[1]) {
				continue
			}
			ok := d.validate(raw)
			if !ok && requiresValidation(d.typ) {
				continue
			}
			all = append(all, Match{Type: d.typ, Start: loc[0], End: loc[1], Value: raw, Validated: ok})
		}
	}
	return dedupe(all)
}

// ScanTypes is Scan restricted to a set of types. An empty set means all.
func ScanTypes(text string, types []Type) []Match {
	matches := Scan(text)
	if len(types) == 0 {
		return matches
	}
	want := map[Type]bool{}
	for _, t := range types {
		want[t] = true
	}
	out := matches[:0]
	for _, m := range matches {
		if want[m.Type] {
			out = append(out, m)
		}
	}
	return out
}

// plausible rejects matches whose surroundings say they are something else:
// the password in a connection string is not an email address, and a phone
// number is not a slice out of a longer token.
func plausible(t Type, text string, start, end int) bool {
	before := byte(0)
	if start > 0 {
		before = text[start-1]
	}
	after := byte(0)
	if end < len(text) {
		after = text[end]
	}
	switch t {
	case Email:
		// userinfo in a URL: "postgres://app:secret@host/db"
		if before == ':' || before == '/' || before == '@' {
			return false
		}
	case Phone, SSN, CreditCard:
		if isDigit(before) || isDigit(after) {
			return false
		}
		// A run inside a longer token ("xoxb-2451234567-98765") is not a
		// number a person would dial.
		if (before == '-' && start >= 2 && isDigit(text[start-2])) ||
			(after == '-' && end+1 < len(text) && isDigit(text[end+1])) {
			return false
		}
	}
	return true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// requiresValidation lists the types whose pattern alone is too loose to
// report: a run of digits is not a card number until Luhn says so.
func requiresValidation(t Type) bool {
	switch t {
	case CreditCard, SSN, IBAN, IPAddress:
		return true
	}
	return false
}

func dedupe(in []Match) []Match {
	if len(in) < 2 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Start != in[j].Start {
			return in[i].Start < in[j].Start
		}
		if in[i].Severity() != in[j].Severity() {
			return in[i].Severity() > in[j].Severity()
		}
		return in[i].End-in[i].Start > in[j].End-in[j].Start
	})
	out := make([]Match, 0, len(in))
	for _, m := range in {
		overlapped := false
		for _, kept := range out {
			if m.Start < kept.End && kept.Start < m.End {
				overlapped = true
				break
			}
		}
		if !overlapped {
			out = append(out, m)
		}
	}
	return out
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhn is the card checksum. It also rejects lengths no issuer uses.
func luhn(s string) bool {
	d := digits(s)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// validSSN applies the SSA's allocation rules: no zero group, no 666 or 9xx
// area, which removes most of the phone-number and id-number noise.
func validSSN(s string) bool {
	d := digits(s)
	if len(d) != 9 {
		return false
	}
	area, group, serial := d[0:3], d[3:5], d[5:9]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// validIBAN is the mod-97 check from ISO 13616.
func validIBAN(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, r := range rearranged {
		var n int
		switch {
		case r >= '0' && r <= '9':
			n = int(r - '0')
			rem = (rem*10 + n) % 97
		case r >= 'A' && r <= 'Z':
			n = int(r-'A') + 10
			rem = (rem*100 + n) % 97
		default:
			return false
		}
	}
	return rem == 1
}

func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	small := 0
	for _, p := range parts {
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		n := 0
		for _, r := range p {
			n = n*10 + int(r-'0')
		}
		if n > 255 {
			return false
		}
		if n < 10 {
			small++
		}
	}
	// A dotted quad of single digits is a version string far more often than an
	// address ("go 1.2.3.4"), so it is not reported. This is a deliberate recall
	// trade documented in docs/failure-modes.md.
	return small < 4
}
