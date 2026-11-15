package server

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	nonDigits   = regexp.MustCompile(`\D`)
	domainShape = regexp.MustCompile(`^([a-z0-9-]+\.)+[a-z]{2,}$`)
	emailShape  = regexp.MustCompile(`^[^@\s]+@([a-z0-9-]+\.)+[a-z]{2,}$`)
)

// normalizeSender returns the senders.value for a reported phone number
// (E.164), website (lowercase host) or email address (lowercase).
func normalizeSender(kind, value string) (string, error) {
	value = strings.TrimSpace(value)

	switch kind {
	case "phone":
		digits := nonDigits.ReplaceAllString(value, "")
		switch {
		case len(digits) == 10:
			return "+1" + digits, nil
		case len(digits) == 11 && digits[0] == '1':
			return "+" + digits, nil
		case strings.HasPrefix(value, "+") && len(digits) >= 8 && len(digits) <= 15:
			return "+" + digits, nil
		}
		return "", errors.New("Please enter a valid phone number, for example 416-555-0142.")
	case "domain":
		raw := strings.ToLower(value)
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		host := ""
		if err == nil {
			host = strings.TrimPrefix(u.Hostname(), "www.")
		}
		if len(host) > 253 || !domainShape.MatchString(host) {
			return "", errors.New("Please enter a valid website, for example canada-post-redelivery.com.")
		}
		return host, nil
	case "email":
		email := strings.ToLower(value)
		if len(email) > 254 || !emailShape.MatchString(email) {
			return "", errors.New("Please enter a valid email address.")
		}
		return email, nil
	}
	return "", errors.New("Please choose the sender type.")
}
