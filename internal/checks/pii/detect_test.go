package pii

import "testing"

func TestLuhnSeparatesCardsFromReferenceNumbers(t *testing.T) {
	cards := []string{"4242 4242 4242 4242", "4111-1111-1111-1111", "5555555555554444"}
	for _, c := range cards {
		if !luhn(c) {
			t.Errorf("luhn(%q) = false, want true", c)
		}
	}
	notCards := []string{"1234 5678 9012 3456", "9876543210987654", "4242424242424243"}
	for _, c := range notCards {
		if luhn(c) {
			t.Errorf("luhn(%q) = true, want false", c)
		}
	}
}

func TestValidSSNAppliesAllocationRules(t *testing.T) {
	cases := map[string]bool{
		"123-45-6789": true,
		"000-45-6789": false,
		"666-45-6789": false,
		"900-45-6789": false,
		"123-00-6789": false,
		"123-45-0000": false,
	}
	for in, want := range cases {
		if got := validSSN(in); got != want {
			t.Errorf("validSSN(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidIBANUsesMod97(t *testing.T) {
	if !validIBAN("GB82WEST12345698765432") {
		t.Error("a valid IBAN was rejected")
	}
	if validIBAN("GB00WEST12345698765432") {
		t.Error("an IBAN with a wrong check digit was accepted")
	}
}

func TestScanReportsSpansThatPointAtTheValue(t *testing.T) {
	text := "card 4242 4242 4242 4242 on file"
	matches := Scan(text)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(matches), matches)
	}
	m := matches[0]
	if got := text[m.Start:m.End]; got != "4242 4242 4242 4242" {
		t.Errorf("span covers %q", got)
	}
	if m.Type != CreditCard || !m.Validated {
		t.Errorf("got %+v, want a validated credit card", m)
	}
}

func TestScanIgnoresUserinfoAndEmbeddedDigitRuns(t *testing.T) {
	// The password in a connection string is not an email address.
	if got := Scan("postgres://app:s3cr3tpassw0rd@db.internal:5432/refunds"); len(got) != 0 {
		t.Errorf("got %+v, want no PII in a connection string", got)
	}
	// A digit run inside a longer token is not a phone number.
	if got := Scan("token xoxb-2451234567-9876543210-aBcDeFgH"); len(got) != 0 {
		t.Errorf("got %+v, want no PII in an opaque token", got)
	}
}

func TestMaskKeepsTheTailAndHidesTheRest(t *testing.T) {
	if got := Mask(CreditCard, "4242 4242 4242 4242"); got != "card ****4242" {
		t.Errorf("Mask = %q", got)
	}
	if got := Mask(Email, "dana.reyes@example.com"); got != "d***@example.com" {
		t.Errorf("Mask = %q", got)
	}
}
