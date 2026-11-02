// internal/rules/rules.go
// Everything that DEFINES a rule: weights, thresholds, keyword patterns and lists.
// To change a score or add a keyword, edit this file.
package rules

import "regexp"

// ---- Tuning knobs: change scores here ----
const (
	urlReputationWeight = 50.0
	mediumThreshold     = 30.0
	highThreshold       = 60.0

	weightShortURL        = 15.0
	weightLookalikeDomain = 35.0
	weightMismatchedLink  = 25.0
)

// Shortened-link services checked by SHORT_URL.
var shorteners = map[string]bool{"bit.ly": true, "tinyurl.com": true, "t.co": true, "is.gd": true}

// A few two-part suffixes so "bbc.co.uk" is treated as the registrable domain, not "co.uk"
var secondLevel = map[string]bool{
	"co.uk": true, "com.au": true, "co.nz": true, "co.in": true, "com.br": true, "gc.ca": true,
}

// Brands checked by LOOKALIKE_DOMAIN: add a brand and its real domains here.
type brand struct {
	name     string   // lowercase token to look for
	official []string // domains that legitimately belong to the brand
}

// Extend this list as you see scams. 
var brands = []brand{
	{"paypal", []string{"paypal.com"}},
	{"amazon", []string{"amazon.com", "amazon.ca"}},
	{"apple", []string{"apple.com", "icloud.com"}},
	{"microsoft", []string{"microsoft.com", "live.com", "office.com", "outlook.com"}},
	{"google", []string{"google.com", "gmail.com"}},
	{"netflix", []string{"netflix.com"}},
	{"canadapost", []string{"canadapost.ca", "canadapost-postescanada.ca"}},
	{"cra", []string{"canada.ca", "gc.ca"}},
	{"rbc", []string{"rbc.com", "rbcroyalbank.com"}},
	{"td", []string{"td.com", "tdcanadatrust.com"}},
	{"scotiabank", []string{"scotiabank.com"}},
	{"bmo", []string{"bmo.com"}},
	{"cibc", []string{"cibc.com"}},
	{"interac", []string{"interac.ca"}},
	{"fedex", []string{"fedex.com"}},
	{"ups", []string{"ups.com"}},
	{"dhl", []string{"dhl.com"}},
	{"facebook", []string{"facebook.com"}},
	{"instagram", []string{"instagram.com"}},
	{"whatsapp", []string{"whatsapp.com"}},
}

// Defaults lists every rule with its weight in one place.
func Defaults() []Rule {
	return []Rule{
		regexRule{"URGENT_LANGUAGE", 15, regexp.MustCompile(`(?i)act now|within 24 hours|final notice|account (will be )?suspended`)},
		regexRule{"GIFT_CARD", 35, regexp.MustCompile(`(?i)gift ?cards?`)},
		regexRule{"PAYMENT_REQUEST", 25, regexp.MustCompile(`(?i)wire transfer|e-?transfer|bitcoin|crypto`)},
		shortURLRule{},
		lookalikeDomainRule{},
		mismatchedLinkRule{},
		regexRule{"IMPERSONATION", 20, regexp.MustCompile(
			`(?i)canada revenue agency|\bcra\b|service canada|\brcmp\b|royal canadian mounted|canada border services|\bcbsa\b|\birs\b|canada post|\bpolice (officer|department)|fraud (department|team)|security (department|team)|(microsoft|apple|windows) (tech(nical)? )?support`)},
		regexRule{"THREAT_OR_ARREST", 25, regexp.MustCompile(
			`(?i)\barrest(ed)?\b|\bwarrant\b|legal action|\blawsuit\b|will sue|\bdeport(ed|ation)?\b|\bprosecut(e|ed|ion)\b|criminal charges|account (will be |has been )?(closed|terminated|frozen|locked|deactivated)|\bjail\b`)},
		regexRule{"PRIZE_OR_TOO_GOOD", 20, regexp.MustCompile(
			`(?i)\byou['’]?(ve| have)? (been selected|won (a|an|the|\$|\d))|you (are|were) (selected|chosen)|congratulations[!,.]?\s+you|claim your (prize|reward|winnings|gift)|\blottery\b|sweepstakes|free (iphone|gift card)|guaranteed (income|returns?|profits?)|make money fast|no experience (needed|required|necessary)|earn \$?\d+[^.]{0,25}(a|per|every|each) (day|week|hour)`)},
		regexRule{"OFF_PLATFORM_CONTACT", 15, regexp.MustCompile(
			`(?i)\b(contact|message|text|chat|reach|add|dm|write to|talk to)\b[^.!?\n]{0,40}\b(on|via|through|at)\s+(whatsapp|telegram|wechat|signal|viber)\b|\b(whatsapp|telegram|wechat)\s+(me|us)\b`)},
		regexRule{"SECRECY", 15, regexp.MustCompile(
			`(?i)don['’]?t tell (anyone|anybody|your (family|bank|husband|wife|friends))|do not (tell|discuss|share this with)|keep (this|it) (a )?(secret|confidential|private)|between you and me|strictly confidential|tell no one|don['’]?t (let|inform) (anyone|your bank)`)},
	}
}
