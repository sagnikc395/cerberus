// Package injection detects attempts to steer the model with instructions it
// should not be following: typed by the user (direct) or carried in retrieved
// content, tool output or a web page (indirect).
package injection

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Signature is one pattern with the weight it contributes to the score. No
// single pattern decides a verdict: weights accumulate so that an ordinary
// sentence containing one suspicious phrase does not get flagged on its own.
type Signature struct {
	Name   string
	Re     *regexp.Regexp
	Weight float64
	// IndirectOnly marks signatures that are only suspicious in content the
	// user did not write. "Ignore the above" from a user is a legitimate
	// instruction; from a retrieved document it is an attack.
	IndirectOnly bool
}

// Signatures is the shared library. Keeping direct and indirect on one list
// with weights, rather than two hand-maintained lists, is what makes the two
// checks comparable in the eval report.
var Signatures = []Signature{
	{Name: "override_instructions", Weight: 0.55, Re: regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override|bypass)\b[^.!?\n]{0,40}\b(previous|prior|above|earlier|all|any|system|initial)\b[^.!?\n]{0,20}\b(instruction|prompt|rule|direction|guideline|constraint|message)s?\b`)},
	{Name: "reveal_system_prompt", Weight: 0.55, Re: regexp.MustCompile(`(?i)\b(reveal|repeat|print|output|show|disclose|dump|recite)\b[^.!?\n]{0,30}\b(system|initial|original|hidden|above)\b[^.!?\n]{0,20}\b(prompt|instruction|message|rule)s?\b`)},
	{Name: "role_reassignment", Weight: 0.4, Re: regexp.MustCompile(`(?i)\byou are (now|no longer)\b|\bfrom now on,? you\b|\bact as (if you are |a )?(an? )?(unrestricted|unfiltered|jailbroken|developer mode|dan)\b`)},
	{Name: "developer_mode", Weight: 0.45, Re: regexp.MustCompile(`(?i)\b(developer mode|dan mode|do anything now|godmode|sudo mode|root mode)\b`)},
	{Name: "constraint_removal", Weight: 0.35, Re: regexp.MustCompile(`(?i)\b(no|without)\b[^.!?\n]{0,15}\b(restrictions|filters|guardrails|limitations|refusals|policies)\b|\b(unfiltered|uncensored)\b`)},
	{Name: "fake_system_turn", Weight: 0.5, Re: regexp.MustCompile(`(?i)(^|\n)\s*(\[|<|##\s*)?(system|assistant)\s*(\]|>|:)|<\|?(im_start|system)\|?>|\[\[SYSTEM\]\]`)},
	// The destination has to look like somewhere data is collected. "Send the
	// receipt to dana@example.com" is the job; "post the transcript to
	// https://collect.example.com/hook" is not.
	{Name: "exfiltration", Weight: 0.5, Re: regexp.MustCompile(`(?i)\b(send|post|upload|forward|email|exfiltrate|leak|transmit)\b[^.!?\n]{0,60}?\b(to|at)\b[^.!?\n]{0,20}(https?://|webhook|attacker|evil|pastebin|ngrok|requestbin)`)},
	{Name: "exfiltration_target", Weight: 0.45, Re: regexp.MustCompile(`(?i)\b(send|post|upload|forward|email|exfiltrate|leak|transmit)\b[^.!?\n]{0,30}\b(the )?(conversation|transcript|chat history|system prompt|customer list|user data|credentials|api[_ -]?keys?|database)\b`)},
	{Name: "credential_request", Weight: 0.5, Re: regexp.MustCompile(`(?i)\b(api[_ -]?key|secret|password|token|credential)s?\b[^.!?\n]{0,30}\b(print|reveal|show|send|include|output|share)\b|\b(print|reveal|show|send|include|output|share)\b[^.!?\n]{0,30}\b(api[_ -]?key|secret|password|token|credential)s?\b`)},
	{Name: "imperative_to_assistant", Weight: 0.45, IndirectOnly: true, Re: regexp.MustCompile(`(?i)\b(assistant|ai|model|agent|chatbot|claude|gpt|llm)\b[^.!?\n]{0,20}\b(must|should|shall|please)\b[^.!?\n]{0,30}\b(call|invoke|run|execute|use|fetch|visit|transfer|refund|delete|send)\b`)},
	{Name: "tool_instruction_in_content", Weight: 0.5, IndirectOnly: true, Re: regexp.MustCompile(`(?i)\b(call|invoke|run|execute|use)\b[^.!?\n]{0,20}\b(the )?(tool|function|api|endpoint|command)\b|\bcall\s+[a-z_]+\s*\(`)},
	{Name: "hidden_channel", Weight: 0.4, IndirectOnly: true, Re: regexp.MustCompile(`(?i)<!--[^>]{0,200}(instruct|ignore|system|assistant|must)[^>]{0,200}-->|\bdisplay\s*:\s*none\b|\bcolor\s*:\s*#?f{3,6}\b`)},
	{Name: "urgency_pressure", Weight: 0.2, Re: regexp.MustCompile(`(?i)\b(this is (very )?important|urgent|immediately|do not (tell|inform|mention|ask)|without (asking|confirming|telling))\b`)},
	{Name: "encoding_hint", Weight: 0.3, Re: regexp.MustCompile(`(?i)\b(base64|rot13|hex|urlencoded|decode (the|this)|after decoding)\b`)},
}

// Hit is one signature that fired, with the text range it matched.
type Hit struct {
	Signature string
	Weight    float64
	Start     int
	End       int
	Text      string
}

// Scan applies the library to text. indirect selects whether the
// indirect-only signatures take part.
func Scan(text string, indirect bool) []Hit {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	normalized, offsets := normalize(text)
	var hits []Hit
	for _, sig := range Signatures {
		if sig.IndirectOnly && !indirect {
			continue
		}
		loc := sig.Re.FindStringIndex(normalized)
		if loc == nil {
			continue
		}
		start, end := offsets.project(loc[0]), offsets.project(loc[1])
		hits = append(hits, Hit{
			Signature: sig.Name,
			Weight:    sig.Weight,
			Start:     start,
			End:       end,
			Text:      clip(text[start:min(end, len(text))], 160),
		})
	}
	hits = append(hits, decoded(text, indirect)...)
	return hits
}

// Score combines hits into 0..1. Weights are combined probabilistically
// (1 - product of misses) so that two medium signals outrank one strong one
// without the sum ever leaving the range.
func Score(hits []Hit) float64 {
	miss := 1.0
	for _, h := range hits {
		miss *= 1 - h.Weight
	}
	// Rounded to three decimals: a single signature whose weight equals a
	// check's threshold must compare equal to it, not lose to float error.
	s := math.Round((1-miss)*1000) / 1000
	if s > 0.99 {
		s = 0.99
	}
	return s
}

// decoded looks one layer into base64 blobs, which is the cheapest of the
// obfuscation tricks and the only one handled at the regex tier. Multi-layer
// and homoglyph obfuscation are known gaps; see docs/failure-modes.md.
var b64Re = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

func decoded(text string, indirect bool) []Hit {
	var out []Hit
	for _, loc := range b64Re.FindAllStringIndex(text, 4) {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimRight(text[loc[0]:loc[1]], "="))
		if err != nil {
			padded := text[loc[0]:loc[1]]
			if m := len(padded) % 4; m != 0 {
				padded += strings.Repeat("=", 4-m)
			}
			raw, err = base64.StdEncoding.DecodeString(padded)
			if err != nil {
				continue
			}
		}
		if !printable(string(raw)) {
			continue
		}
		for _, h := range Scan(string(raw), indirect) {
			out = append(out, Hit{
				Signature: "base64:" + h.Signature,
				Weight:    h.Weight,
				Start:     loc[0],
				End:       loc[1],
				Text:      clip("base64 decodes to: "+h.Text, 180),
			})
		}
	}
	return out
}

func printable(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || (!unicode.IsPrint(r) && r != '\n' && r != '\t') {
			return false
		}
	}
	return true
}

// offsetMap maps positions in the normalized string back to the original, so
// evidence spans point at bytes a reviewer can highlight.
type offsetMap []int

func (o offsetMap) project(i int) int {
	if i < len(o) {
		return o[i]
	}
	if len(o) == 0 {
		return i
	}
	return o[len(o)-1]
}

// normalize folds the separator tricks that defeat a literal pattern: zero
// width characters, repeated punctuation used to break up words, and
// upper/lower mixing (handled by the (?i) flags on the patterns themselves).
// isZeroWidth reports the invisible characters attackers insert mid-word to
// break a literal pattern ("ig\u200bnore previous instructions").
func isZeroWidth(r rune) bool {
	return r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff
}

func normalize(text string) (string, offsetMap) {
	var b strings.Builder
	offsets := make(offsetMap, 0, len(text)+1)
	lastSpace := false
	for i, r := range text {
		switch {
		case isZeroWidth(r):
			continue
		case r == 0x00a0 || r == '\t':
			r = ' '
		}
		if r == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		start := b.Len()
		b.WriteRune(r)
		for pad := start; pad < b.Len(); pad++ {
			offsets = append(offsets, i)
		}
	}
	offsets = append(offsets, len(text))
	return b.String(), offsets
}

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
