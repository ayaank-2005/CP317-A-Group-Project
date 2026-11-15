// internal/rules/risk_engine.go
// The logic: rule types, link helpers, matching code and the scoring engine.
// Weights, patterns and lists are defined in rules.go.
package rules

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Input struct {
	Type string // "text" | "url" | "email"
	Text string
	URLs []string
}

// Rule is one check. Weight is the points added when it fires.
type Rule interface {
	Code() string
	Weight() float64
	Match(in Input) bool
}

type Reputation interface {
	Check(ctx context.Context, rawURL string) (malicious bool, err error)
}

// ---- generic regex rule ----

type regexRule struct {
	code   string
	weight float64
	re     *regexp.Regexp
}

func (r regexRule) Code() string        { return r.code }
func (r regexRule) Weight() float64     { return r.weight }
func (r regexRule) Match(in Input) bool { return r.re.MatchString(in.Text) }

// ---- URL helpers shared by the link-based rules ----

// Finds domain-like strings in plain text, e.g. "paypa1-secure.com" in an email address or sentence
var bareDomainRe = regexp.MustCompile(`[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+`)

func hostOf(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// registrable returns the "owner" part of a host: mail.paypal.com -> paypal.com
func registrable(host string) string {
	labels := strings.Split(host, ".")
	n := len(labels)
	if n <= 2 {
		return host
	}
	last2 := strings.Join(labels[n-2:], ".")
	if secondLevel[last2] {
		return strings.Join(labels[n-3:], ".")
	}
	return last2
}

// hostsIn collects every host mentioned in the submission (links and bare domains)
func hostsIn(in Input) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, raw := range in.URLs {
		add(hostOf(raw))
	}
	for _, m := range bareDomainRe.FindAllString(strings.ToLower(in.Text), -1) {
		add(m)
	}
	return out
}

// ---- SHORT_URL (also catches links pasted without https://, e.g. bit.ly/abc) ----

type shortURLRule struct{}

func (shortURLRule) Code() string    { return "SHORT_URL" }
func (shortURLRule) Weight() float64 { return weightShortURL }
func (shortURLRule) Match(in Input) bool {
	for _, host := range hostsIn(in) {
		if shorteners[host] {
			return true
		}
	}
	return false
}

// ---- LOOKALIKE_DOMAIN ----

// Swaps characters scammers use to imitate letters: paypa1 -> paypal, rnicrosoft -> microsoft
var confusables = strings.NewReplacer("0", "o", "1", "l", "3", "e", "5", "s", "rn", "m", "vv", "w")

func deconfuse(s string) string { return confusables.Replace(s) }

func isOfficial(host string, official []string) bool {
	for _, d := range official {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// mentionsBrand: does the host use the brand name (or a look-alike spelling) outside the TLD?
func mentionsBrand(host, name string) bool {
	labels := strings.Split(host, ".")
	if len(labels) > 1 {
		labels = labels[:len(labels)-1] // ignore the TLD
	}
	for _, label := range labels {
		for _, token := range strings.Split(label, "-") {
			if token == name || deconfuse(token) == name {
				return true
			}
		}
		// Longer brand names are also caught when glued to other words: paypalsecure.com
		if len(name) >= 6 && (strings.Contains(label, name) || strings.Contains(deconfuse(label), name)) {
			return true
		}
	}
	return false
}

type lookalikeDomainRule struct{}

func (lookalikeDomainRule) Code() string    { return "LOOKALIKE_DOMAIN" }
func (lookalikeDomainRule) Weight() float64 { return weightLookalikeDomain }
func (lookalikeDomainRule) Match(in Input) bool {
	for _, host := range hostsIn(in) {
		for _, b := range brands {
			if isOfficial(host, b.official) {
				continue // the real site is fine
			}
			if mentionsBrand(host, b.name) {
				return true
			}
		}
	}
	return false
}

// ---- MISMATCHED_LINK ----
// Only detectable when the pasted text keeps link markup: HTML <a href> or [text](url).
// Plain pasted text has no hidden targets to compare.

var (
	htmlLinkRe = regexp.MustCompile(`(?is)<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>`)
	mdLinkRe   = regexp.MustCompile(`\[([^\]]+)\]\((https?://[^)\s]+)\)`)
)

func linkMismatch(shown, target string) bool {
	shownDomain := bareDomainRe.FindString(strings.ToLower(shown))
	if shownDomain == "" {
		return false // link text like "Click here" shows no domain to compare
	}
	targetHost := hostOf(target)
	if targetHost == "" {
		return false
	}
	return registrable(shownDomain) != registrable(targetHost)
}

type mismatchedLinkRule struct{}

func (mismatchedLinkRule) Code() string    { return "MISMATCHED_LINK" }
func (mismatchedLinkRule) Weight() float64 { return weightMismatchedLink }
func (mismatchedLinkRule) Match(in Input) bool {
	for _, m := range htmlLinkRe.FindAllStringSubmatch(in.Text, -1) {
		if linkMismatch(m[2], m[1]) { // m[1]=href, m[2]=visible text
			return true
		}
	}
	for _, m := range mdLinkRe.FindAllStringSubmatch(in.Text, -1) {
		if linkMismatch(m[1], m[2]) { // m[1]=visible text, m[2]=url
			return true
		}
	}
	return false
}

// ---- engine: DO NOT CHANGE ----

type Result struct {
	Score    float64  `json:"score"`
	Level    string   `json:"level"`
	Reasons  []string `json:"reasons"`
	URLCheck string   `json:"urlCheck"` // not_applicable | ok | unavailable
}

type Engine struct {
	rules []Rule
	rep   Reputation // may be nil
}

func NewEngine(rules []Rule, rep Reputation) *Engine {
	return &Engine{rules: rules, rep: rep}
}

func (e *Engine) Assess(ctx context.Context, in Input) Result {
	res := Result{URLCheck: "not_applicable", Reasons: []string{}}

	type repOut struct {
		bad bool
		err error
	}
	var ch chan repOut
	if e.rep != nil && len(in.URLs) > 0 {
		ch = make(chan repOut, 1)
		go func() {
			rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			bad, err := e.rep.Check(rctx, in.URLs[0])
			ch <- repOut{bad, err}
		}()
	}

	for _, r := range e.rules {
		if r.Match(in) {
			res.Reasons = append(res.Reasons, r.Code())
			res.Score += r.Weight()
		}
	}

	if ch != nil {
		select {
		case o := <-ch:
			switch {
			case o.err != nil:
				res.URLCheck = "unavailable"
			case o.bad:
				res.URLCheck = "ok"
				res.Reasons = append(res.Reasons, "URL_REPUTATION")
				res.Score += urlReputationWeight
			default:
				res.URLCheck = "ok"
			}
		case <-ctx.Done():
			res.URLCheck = "unavailable"
		}
	}

	if res.Score > 100 {
		res.Score = 100
	}
	switch {
	case res.Score >= highThreshold:
		res.Level = "high"
	case res.Score >= mediumThreshold:
		res.Level = "medium"
	default:
		res.Level = "low"
	}
	return res
}
