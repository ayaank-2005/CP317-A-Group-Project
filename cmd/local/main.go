// cmd/local/main.go
// Run all checks:        go run ./cmd/local
// Score your own text:   go run ./cmd/local 'paste a message here'
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"scamshield/internal/rules"
)

var urlRe = regexp.MustCompile(`https?://[^\s]+`)

type testCase struct {
	name        string
	text        string
	wantScore   float64
	wantLevel   string
	wantReasons []string // in the order the rules are listed in Defaults()
}

func assess(eng *rules.Engine, text string) rules.Result {
	in := rules.Input{Type: "text", Text: text, URLs: urlRe.FindAllString(text, -1)}
	return eng.Assess(context.Background(), in)
}

func sameReasons(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func main() {
	eng := rules.NewEngine(rules.Defaults(), nil)

	// Custom mode: score whatever text you pass on the command line
	if len(os.Args) > 1 {
		res := assess(eng, strings.Join(os.Args[1:], " "))
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return
	}

	cases := []testCase{
		// ---- original rules ----
		{"Obvious scam: urgency + gift card + short link",
			"FINAL NOTICE: your account will be suspended. Buy gift cards within 24 hours and send the codes. Details: https://bit.ly/example",
			65, "high", []string{"URGENT_LANGUAGE", "GIFT_CARD", "SHORT_URL"}},
		{"Everything at once",
			"FINAL NOTICE act now: send a wire transfer or gift cards. Details: https://bit.ly/example",
			90, "high", []string{"URGENT_LANGUAGE", "GIFT_CARD", "PAYMENT_REQUEST", "SHORT_URL"}},
		{"Urgency + payment + prize claim",
			"Act now! Send bitcoin to claim your prize",
			60, "high", []string{"URGENT_LANGUAGE", "PAYMENT_REQUEST", "PRIZE_OR_TOO_GOOD"}},
		{"Fake delivery notice",
			"Your parcel could not be delivered. Pay a fee at https://bit.ly/example within 24 hours",
			30, "medium", []string{"URGENT_LANGUAGE", "SHORT_URL"}},
		{"Payment request alone (currently scores low)",
			"Please send an e-transfer to claim your refund",
			25, "low", []string{"PAYMENT_REQUEST"}},
		{"Short link alone",
			"Check this out https://tinyurl.com/example",
			15, "low", []string{"SHORT_URL"}},
		{"Harmless message",
			"Hi, are we still meeting for lunch tomorrow?",
			0, "low", nil},
		{"Legitimate bank-style message",
			"Your statement is ready. Log in to your account to view it.",
			0, "low", nil},

		// ---- new rules ----
		{"Lookalike domain: digit swap (paypa1)",
			"Your PayPal account is limited. Log in at https://paypa1-secure.example/login",
			35, "medium", []string{"LOOKALIKE_DOMAIN"}},
		{"Official domain must NOT be flagged",
			"Your Amazon order has shipped. Track it at https://www.amazon.ca/orders",
			0, "low", nil},
		{"Lookalike domain: brand hidden in subdomain",
			"Verify your Apple ID: https://apple.com.id-verify.example/signin",
			35, "medium", []string{"LOOKALIKE_DOMAIN"}},
		{"Impersonation + threat of arrest",
			"This is the Canada Revenue Agency. A warrant has been issued for your arrest. Pay now or you will be arrested.",
			45, "medium", []string{"IMPERSONATION", "THREAT_OR_ARREST"}},
		{"Prize + secrecy + gift card",
			"Congratulations! You won a $1000 gift card. Don't tell anyone, keep this a secret.",
			70, "high", []string{"GIFT_CARD", "PRIZE_OR_TOO_GOOD", "SECRECY"}},
		{"Job scam moving to WhatsApp",
			"Great job opportunity! No experience needed, earn $500 per day. Text me on WhatsApp +1 555 0100 to start.",
			35, "medium", []string{"PRIZE_OR_TOO_GOOD", "OFF_PLATFORM_CONTACT"}},
		{"Mismatched link (HTML shows rbc.com, goes elsewhere)",
			`Click here: <a href="https://secure-login.example/verify">www.rbc.com</a>`,
			25, "low", []string{"MISMATCHED_LINK"}},
	}

	failed := 0
	for _, c := range cases {
		res := assess(eng, c.text)
		ok := res.Score == c.wantScore && res.Level == c.wantLevel && sameReasons(res.Reasons, c.wantReasons)
		status := "PASS"
		if !ok {
			status = "FAIL"
			failed++
		}
		fmt.Printf("[%s] %s\n", status, c.name)
		fmt.Printf("       got:  score=%v level=%s reasons=%v\n", res.Score, res.Level, res.Reasons)
		if !ok {
			fmt.Printf("       want: score=%v level=%s reasons=%v\n", c.wantScore, c.wantLevel, c.wantReasons)
		}
	}

	fmt.Printf("\n%d/%d passed\n", len(cases)-failed, len(cases))
	if failed > 0 {
		os.Exit(1)
	}
}
