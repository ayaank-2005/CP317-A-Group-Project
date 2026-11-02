// internal/rules/response.go
// Turns the engine's Result into the JSON the scanner page expects.
// The engine in risk_engine.go is not modified.
package rules

import "strings"

// Response is what the page receives. verdict / explanation / flags are the fields the
// scanner script reads; score / level / reasons / urlCheck are kept for any code that wants raw values.
type Response struct {
	Status      string   `json:"status"` // "ok"
	Verdict     string   `json:"verdict"`
	Explanation string   `json:"explanation"`
	Flags       []string `json:"flags"` // plain-language reasons, never empty (UI-2)
	Score       float64  `json:"score"`
	Level       string   `json:"level"`
	Reasons     []string `json:"reasons"` // rule codes
	URLCheck    string   `json:"urlCheck"`
}

type texts struct {
	verdict     map[string]string // by level
	summary     map[string]string // by level
	urlNote     string
	noFlags     string
	unknownFlag string
	flags       map[string]string // by rule code
}

// One entry per language. Add "fr", "pa", etc. here later; unknown languages fall back to English.
var catalog = map[string]texts{
	"en": {
		verdict: map[string]string{
			"low":    "Low risk: no obvious warning signs found",
			"medium": "Medium risk: some warning signs found",
			"high":   "High risk: several strong warning signs found",
		},
		summary: map[string]string{
			"low":    "We did not find strong warning signs in the wording or links. A low score does not guarantee a message is safe, so if anything feels wrong, do not click links, pay, or share personal details.",
			"medium": "This message has some features that scams often use. Check it with the sender using a phone number or website you already trust before you respond.",
			"high":   "This message has several features that scams commonly use. Do not click links, send money, or share personal details. Contact the organization directly using a phone number or website you already trust.",
		},
		urlNote:     "We could not check the link with an online safety service, so this result is based on the message itself.",
		noFlags:     "We did not find known scam wording, suspicious links, or requests for money in this message.",
		unknownFlag: "A warning sign was found in this message.",
		flags: map[string]string{
			"URGENT_LANGUAGE":      "The message pressures you to act quickly. Scammers rush people so they don't have time to think.",
			"GIFT_CARD":            "It mentions gift cards. Real organizations do not ask to be paid with gift cards.",
			"PAYMENT_REQUEST":      "It asks for a money transfer or cryptocurrency, which is very hard to get back once sent.",
			"SHORT_URL":            "It contains a shortened link, which hides where the link really goes.",
			"LOOKALIKE_DOMAIN":     "A website address imitates a well-known company but is not that company's real address.",
			"MISMATCHED_LINK":      "A link shows one website name but actually leads to a different website.",
			"IMPERSONATION":        "It claims to come from a government agency, bank, or company. Scammers often pretend to be trusted organizations.",
			"THREAT_OR_ARREST":     "It threatens arrest, legal action, or closing your account to frighten you into acting.",
			"PRIZE_OR_TOO_GOOD":    "It promises a prize or easy money. Offers that sound too good to be true usually are.",
			"OFF_PLATFORM_CONTACT": "It asks you to move the conversation to a messaging app, away from places where scams can be reported.",
			"SECRECY":              "It asks you to keep this secret. Scammers do this so friends, family, or your bank can't warn you.",
			"URL_REPUTATION":       "An online safety service has flagged a link in this message as dangerous.",
		},
	},
}

// PrimaryLanguage reads an Accept-Language header like "fr-CA,fr;q=0.9,en;q=0.8" and returns "fr".
func PrimaryLanguage(header string) string {
	first := strings.TrimSpace(strings.SplitN(header, ",", 2)[0])
	first = strings.TrimSpace(strings.SplitN(first, ";", 2)[0])
	first = strings.ToLower(strings.SplitN(first, "-", 2)[0])
	if first == "" {
		return "en"
	}
	return first
}

// BuildResponse maps an engine Result onto the page's expected fields, in the user's language when available.
func BuildResponse(res Result, lang string) Response {
	t, found := catalog[lang]
	if !found {
		t = catalog["en"]
	}

	flags := make([]string, 0, len(res.Reasons)+1)
	for _, code := range res.Reasons {
		if text, ok := t.flags[code]; ok {
			flags = append(flags, text)
		} else {
			flags = append(flags, t.unknownFlag)
		}
	}
	if len(flags) == 0 {
		flags = append(flags, t.noFlags) // every result carries at least one reason
	}

	explanation := t.summary[res.Level]
	if res.URLCheck == "unavailable" {
		explanation += " " + t.urlNote
	}

	return Response{
		Status:      "ok",
		Verdict:     t.verdict[res.Level],
		Explanation: explanation,
		Flags:       flags,
		Score:       res.Score,
		Level:       res.Level,
		Reasons:     res.Reasons,
		URLCheck:    res.URLCheck,
	}
}
