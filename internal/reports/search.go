// internal/reports/search.go
// Search for the Public Scam Database page (database.js).
package reports

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DefaultPageSize = 10
	MaxPageSize     = 50
	MaxPage         = 10000
	MaxQueryRunes   = 200 // same limit as MAX_QUERY_LENGTH in database.js
)

// ---- JSON shapes that database.js reads ----

type Category struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type Sender struct {
	Type  string `json:"type"`  // phone | domain | email
	Value string `json:"value"` // phone: +14165550142, domain: lowercase without www.
}

type Report struct {
	ID          string    `json:"id"`
	Category    Category  `json:"category"`
	Sender      *Sender   `json:"sender"`
	Content     string    `json:"content"`
	ReportCount int       `json:"reportCount"`
	ApprovedAt  time.Time `json:"approvedAt"`
	Language    string    `json:"language"`
}

type Page struct {
	Results  []Report `json:"results"`
	Total    int      `json:"total"`
	Page     int      `json:"page"`
	PageSize int      `json:"pageSize"`
}

// ---- request parameters ----

type Params struct {
	Q        string
	Category string
	Page     int
	PageSize int
}

func (p Params) Offset() int { return (p.Page - 1) * p.PageSize }

var ErrBadCategory = errors.New("unknown scam category")
var categoryRe = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)

func clamp(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func ParseParams(v url.Values) (Params, error) {
	p := Params{Page: 1, PageSize: DefaultPageSize}

	q := strings.TrimSpace(v.Get("q"))
	if utf8.RuneCountInString(q) > MaxQueryRunes {
		q = string([]rune(q)[:MaxQueryRunes])
	}
	p.Q = q

	if c := strings.TrimSpace(v.Get("category")); c != "" {
		if !categoryRe.MatchString(c) {
			return p, ErrBadCategory
		}
		p.Category = c
	}
	if n, err := strconv.Atoi(v.Get("page")); err == nil {
		p.Page = clamp(n, 1, MaxPage)
	}
	if n, err := strconv.Atoi(v.Get("pageSize")); err == nil {
		p.PageSize = clamp(n, 1, MaxPageSize)
	}
	return p, nil
}

// ---- what kind of thing did the user type? ----

type kind int

const (
	kindNone      kind = iota
	kindPhone          // a full phone number: exact match
	kindPhonePart      // part of a phone number (4+ digits): contains match
	kindEmail
	kindDomain // a website address or domain name
	kindText   // anything else: keywords
)

type search struct {
	kind  kind
	value string
}

var (
	phoneChars = regexp.MustCompile(`^[+\d\s().-]+$`)
	emailRe    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	hostRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	ipRe       = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
)

func digitsOf(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

// NormalizePhone turns a North American number in any common format into +1XXXXXXXXXX,
// the form stored in senders.value. Reuse it when saving a reported sender (UI-3),
// so what is stored and what is searched always match.
func NormalizePhone(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !phoneChars.MatchString(s) {
		return "", false
	}
	d := digitsOf(s)
	switch {
	case len(d) == 10:
		return "+1" + d, true
	case len(d) == 11 && d[0] == '1':
		return "+" + d, true
	}
	return "", false
}
func hostFrom(q string) string {
	s := strings.ToLower(strings.TrimSpace(q))
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return ""
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "www."), ".")
	if hostRe.MatchString(s) {
		return s
	}
	return ""
}

func classify(q string) search {
	q = strings.TrimSpace(q)
	if q == "" {
		return search{kindNone, ""}
	}
	if !ipRe.MatchString(q) && phoneChars.MatchString(q) {
		if n, ok := NormalizePhone(q); ok {
			return search{kindPhone, n}
		}
		if d := digitsOf(q); len(d) >= 4 && len(d) <= 15 {
			return search{kindPhonePart, d}
		}
	}
	if strings.Contains(q, "://") {
		if h := hostFrom(q); h != "" {
			return search{kindDomain, h}
		}
	}
	if emailRe.MatchString(q) {
		return search{kindEmail, strings.ToLower(q)}
	}
	if h := hostFrom(q); h != "" {
		return search{kindDomain, h}
	}
	return search{kindText, q}
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// ---- SQL ----

// SQL to run and its parameters.  so a search box cannot inject SQL.
type Query struct {
	SQL       string
	Args      []any
	CountSQL  string
	CountArgs []any
}

// Columns come from the public_reports view.
// The order here must match ScanReport!!!!
const selectCols = `p.id::text, p.category, p.category_name, p.sender_type, p.sender, ` +
	`p.redacted_content, p.submission_count, p.approved_at, p.language`

func BuildSearch(p Params) Query {
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}

	where := []string{"true"}
	rank := ""

	if p.Category != "" {
		where = append(where, "p.category = "+arg(p.Category)+"::text")
	}

	s := classify(p.Q)
	switch s.kind {
	case kindPhone:
		where = append(where, "(p.sender_type = 'phone' AND p.sender = "+arg(s.value)+"::text)")
	case kindPhonePart:
		where = append(where, "(p.sender_type = 'phone' AND p.sender LIKE '%' || "+arg(s.value)+"::text || '%')")
	case kindEmail:
		where = append(where, "(p.sender_type = 'email' AND p.sender = "+arg(s.value)+"::text)")
	case kindDomain:
		h := arg(s.value)
		tsq := "websearch_to_tsquery('english', " + h + "::text)"
		where = append(where, "((p.sender_type = 'domain' AND (p.sender = "+h+"::text OR p.sender LIKE '%.' || "+h+"::text)) "+
			"OR p.search_vector @@ "+tsq+")")
		rank = "ts_rank(p.search_vector, " + tsq + ") DESC, "
	case kindText:
		t := arg(s.value)
		l := arg(likeEscaper.Replace(s.value))
		tsq := "websearch_to_tsquery('english', " + t + "::text)"
		where = append(where, "(p.search_vector @@ "+tsq+" OR p.sender ILIKE '%' || "+l+"::text || '%')")
		rank = "ts_rank(p.search_vector, " + tsq + ") DESC, "
	}

	cond := strings.Join(where, " AND ")
	countArgs := append([]any(nil), args...)
	limit := arg(p.PageSize)
	offset := arg(p.Offset())

	return Query{
		SQL: "SELECT " + selectCols + " FROM public_reports p WHERE " + cond +
			" ORDER BY " + rank + "p.approved_at DESC, p.id" +
			" LIMIT " + limit + "::bigint OFFSET " + offset + "::bigint",
		Args:      args,
		CountSQL:  "SELECT count(*) FROM public_reports p WHERE " + cond,
		CountArgs: countArgs,
	}
}

// ScanReport reads one row produced by BuildSearch. Pass rows.Scan.
func ScanReport(scan func(dest ...any) error) (Report, error) {
	var r Report
	var senderType, senderValue *string
	if err := scan(&r.ID, &r.Category.Code, &r.Category.Name, &senderType, &senderValue,
		&r.Content, &r.ReportCount, &r.ApprovedAt, &r.Language); err != nil {
		return r, err
	}
	if senderType != nil && senderValue != nil {
		r.Sender = &Sender{Type: *senderType, Value: *senderValue}
	}
	return r, nil
}

