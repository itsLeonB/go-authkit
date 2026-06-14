package authkit

import (
	"regexp"
	"strings"
	"unicode"
)

var reAlpha = regexp.MustCompile(`[a-zA-Z]+`)

// nameFromEmail extracts a capitalized name from the local part of an email.
func nameFromEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) < 2 || parts[0] == "" {
		return ""
	}
	matches := reAlpha.FindAllString(parts[0], -1)
	if len(matches) == 0 {
		return ""
	}
	name := matches[0]
	r := []rune(name)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
