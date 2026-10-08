package redact

import (
	"fmt"
	"strings"
)

// Format-preserving generators keep the layout of the original value, so the
// fake reads like the original: separators, letter case, length and the
// leading part that identifies the kind of value stay the same, while every
// other character changes.

const (
	minIBANLen     = 15
	maxIBANLen     = 34
	maxPhoneDigits = 20
	// A phone fake must change at least this many digits.
	minPhoneReplacedDigits = 4
)

func isASCIIDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isASCIILetter(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
func isASCIIAlnum(c byte) bool  { return isASCIIDigit(c) || isASCIILetter(c) }

// shiftDigit changes a digit by a nonzero amount derived from b.
func shiftDigit(c, b byte) byte { return '0' + (c-'0'+1+b%9)%10 }

// shiftLetter changes a letter by a nonzero amount derived from b and keeps
// its case.
func shiftLetter(c, b byte) byte {
	base := byte('A')
	if c >= 'a' {
		base = 'a'
	}
	return base + (c-base+1+b%25)%26
}

// fillLayout writes chars into the positions of original whose byte
// satisfies keep, and copies every other byte unchanged.
func fillLayout(original string, chars []byte, keep func(byte) bool) string {
	var out strings.Builder
	out.Grow(len(original))
	n := 0
	for i := 0; i < len(original); i++ {
		if c := original[i]; keep(c) {
			out.WriteByte(chars[n])
			n++
		} else {
			out.WriteByte(c)
		}
	}
	return out.String()
}

// generateIBANReplacement keeps the country code and layout of original and
// replaces every character of the account part, then sets check digits that
// make the fake a valid IBAN: the ISO 13616 check digits and, for countries
// whose account part carries its own check digits, those as well.
func generateIBANReplacement(original string, h [32]byte) (string, error) {
	chars := make([]byte, 0, maxIBANLen)
	for i := 0; i < len(original); i++ {
		if c := original[i]; isASCIIAlnum(c) {
			if len(chars) == maxIBANLen {
				return "", fmt.Errorf("invalid IBAN")
			}
			chars = append(chars, c)
		}
	}
	if len(chars) < minIBANLen || !isASCIILetter(chars[0]) || !isASCIILetter(chars[1]) ||
		!isASCIIDigit(chars[2]) || !isASCIIDigit(chars[3]) {
		return "", fmt.Errorf("invalid IBAN")
	}
	country := strings.ToUpper(string(chars[:2]))
	bban := chars[4:]
	for i, c := range bban {
		if isASCIIDigit(c) {
			bban[i] = shiftDigit(c, h[i])
		} else {
			bban[i] = shiftLetter(c, h[i])
		}
	}
	setNationalCheckDigits(country, bban)
	check := 98 - ibanMod97(bban, country, "00")
	chars[2], chars[3] = '0'+byte(check/10), '0'+byte(check%10)
	return fillLayout(original, chars, isASCIIAlnum), nil
}

// setNationalCheckDigits rewrites the check digits that some countries embed
// in the account part, so a fake also passes national validation.
func setNationalCheckDigits(country string, bban []byte) {
	switch country {
	case "BE":
		// Ten account digits followed by the account modulo 97, with 97 for 0.
		if len(bban) != 12 || !allASCIIDigits(string(bban)) {
			return
		}
		rem := 0
		for _, c := range bban[:10] {
			rem = (rem*10 + int(c-'0')) % 97
		}
		if rem == 0 {
			rem = 97
		}
		bban[10], bban[11] = '0'+byte(rem/10), '0'+byte(rem%10)
	}
}

// ibanMod97 computes the ISO 13616 remainder of the account part followed by
// the country code and check digits, with letters read as 10 to 35.
func ibanMod97(bban []byte, country, check string) int {
	rem := 0
	feed := func(c byte) {
		if isASCIIDigit(c) {
			rem = (rem*10 + int(c-'0')) % 97
			return
		}
		rem = (rem*100 + int(c|0x20-'a') + 10) % 97
	}
	for _, c := range bban {
		feed(c)
	}
	for i := 0; i < len(country); i++ {
		feed(country[i])
	}
	for i := 0; i < len(check); i++ {
		feed(check[i])
	}
	return rem
}

// generatePhoneReplacement keeps the layout of original, its international
// prefix and country code, a trunk zero, and the first digit of the national
// number, and changes every remaining digit.
func generatePhoneReplacement(original string, h [32]byte) (string, error) {
	digits := make([]byte, 0, maxPhoneDigits)
	plus := false
	for i := 0; i < len(original); i++ {
		switch c := original[i]; {
		case isASCIIDigit(c):
			if len(digits) == maxPhoneDigits {
				return "", fmt.Errorf("invalid phone number")
			}
			digits = append(digits, c)
		case c == '+' && len(digits) == 0:
			plus = true
		}
	}
	keep, international := 0, plus
	switch {
	case plus:
		keep = countryCodeLen(digits)
	case len(digits) >= 2 && digits[0] == '0' && digits[1] == '0':
		keep, international = 2+countryCodeLen(digits[2:]), true
	case len(digits) >= 1 && digits[0] == '0':
		keep = 1
	}
	if international && keep < len(digits) && digits[keep] == '0' {
		keep++ // A trunk zero written after the country code, as in +32 (0)4.
	}
	if keep < len(digits) {
		keep++ // The first digit of the national number.
	}
	if len(digits)-keep < minPhoneReplacedDigits {
		return "", fmt.Errorf("invalid phone number")
	}
	for i := keep; i < len(digits); i++ {
		digits[i] = shiftDigit(digits[i], h[i])
	}
	return fillLayout(original, digits, isASCIIDigit), nil
}

// generateDigitsReplacement keeps every non-digit byte of original and
// changes every digit, for identifiers whose layout should survive.
func generateDigitsReplacement(original string, h [32]byte) (string, error) {
	digits := make([]byte, 0, len(original))
	for i := 0; i < len(original); i++ {
		if c := original[i]; isASCIIDigit(c) {
			digits = append(digits, shiftDigit(c, h[len(digits)%len(h)]))
		}
	}
	if len(digits) < minPhoneReplacedDigits {
		return "", fmt.Errorf("too few digits")
	}
	return fillLayout(original, digits, isASCIIDigit), nil
}

// countryCodeLen returns the length of the E.164 country code that starts
// digits: one digit for zones 1 and 7, two for the codes listed, three
// otherwise.
func countryCodeLen(digits []byte) int {
	if len(digits) == 0 {
		return 0
	}
	if digits[0] == '1' || digits[0] == '7' {
		return 1
	}
	if len(digits) >= 2 {
		switch string(digits[:2]) {
		case "20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45",
			"46", "47", "48", "49", "51", "52", "53", "54", "55", "56", "57", "58", "60", "61",
			"62", "63", "64", "65", "66", "81", "82", "84", "86", "90", "91", "92", "93", "94",
			"95", "98":
			return 2
		}
	}
	return min(3, len(digits))
}
