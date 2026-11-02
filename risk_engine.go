// internal/rules/engine.go
package rules

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ---- Tuning knobs: change scores here ----
const (
	urlReputationWeight = 50.0
	mediumThreshold     = 30.0
	highThreshold       = 60.0
)

// Input is what every rule sees. Built by the handler after validation.
type Input struct {
	Type string // "text" | "url" | "email"
	Text string
	URLs []string
}

// Rule is one check. Add a new rule by adding a type that implements this.
// Added Weighting rule. 
type Rule interface {
	Code() string
	Weight() float64
	Match(in Input) bool
}

// Reputation is the external URL API. An interface so tests can fake it.
type Reputation interface {
	Check(ctx context.Context, rawURL string) (malicious bool, err error)
}

// ---- rules ----

type regexRule struct {
	code string
	weight float64
	re   *regexp.Regexp
}

func (r regexRule) Code() string        { return r.code }
func (r regexRule) Weight() float64     { return r.weight }
func (r regexRule) Match(in Input) bool { return r.re.MatchString(in.Text) }

type shortURLRule struct{}

func (shortURLRule) Code() string { return "SHORT_URL" }
func (shortURLRule) Weight() float64 { return 15 }
func (shortURLRule) Match(in Input) bool {
	shorteners := map[string]bool{"bit.ly": true, "tinyurl.com": true, "t.co": true, "is.gd": true}
	for _, raw := range in.URLs {
		if u, err := url.Parse(raw); err == nil && shorteners[strings.ToLower(u.Hostname())] {
			return true
		}
	}
	return false
}

// Defaults lists every rule with its weight in one place.
func Defaults() []Rule {
	return []Rule{
		regexRule{"URGENT_LANGUAGE", 15, regexp.MustCompile(`(?i)act now|within 24 hours|final notice|account (will be )?suspended`)},
		regexRule{"GIFT_CARD", 35, regexp.MustCompile(`(?i)gift ?cards?`)},
		regexRule{"PAYMENT_REQUEST", 25, regexp.MustCompile(`(?i)wire transfer|e-?transfer|bitcoin|crypto`)},
		shortURLRule{},
	}
}

// ---- engine ----

type Result struct {
	Score    float64  `json:"score"`
	Level    string   `json:"level"`    // low | medium | high
	Reasons  []string `json:"reasons"`  // rule codes; mapped to plain-language text afterwards
	URLCheck string   `json:"urlCheck"` // not_applicable | ok | unavailable
}

type Engine struct {
	rules   []Rule
	rep     Reputation         // may be nil
}

func NewEngine(rules []Rule, rep Reputation) *Engine {
	return &Engine{rules: rules, rep: rep}
}

func (e *Engine) Assess(ctx context.Context, in Input) Result {
	res := Result{URLCheck: "not_applicable", Reasons: []string{}}

	// Start the slow external call first so it runs while the local rules execute
	type repOut struct {
		bad bool
		err error
	}
	var ch chan repOut
	if e.rep != nil && len(in.URLs) > 0 {
		ch = make(chan repOut, 1) // buffered: goroutine never blocks if we stop waiting
		go func() {
			rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			bad, err := e.rep.Check(rctx, in.URLs[0])
			ch <- repOut{bad, err}
		}()
	}

	// Local rules take microseconds
	for _, r := range e.rules {
		if r.Match(in) {
			res.Reasons = append(res.Reasons, r.Code())
			res.Score += r.Weight()
		}
	}

	// Collect the reputation result, or give up when the request deadline hits
	if ch != nil {
		select {
		case o := <-ch:
			switch {
			case o.err != nil:
				res.URLCheck = "unavailable" // rule-based result still returned
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
	case res.Score >= 30:
		res.Level = "mediumThreshold"
	default:
		res.Level = "low"
	}
	return res
}
