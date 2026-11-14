package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newTestServer creates a throwaway database from ScamShield_DB.sql and
// dev_seed.sql. Set TEST_DATABASE_URL to a Postgres server where the user may
// CREATE DATABASE; the tests are skipped otherwise.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	adminURL := os.Getenv("TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database tests")
	}
	ctx := context.Background()

	var b [6]byte
	rand.Read(b[:])
	name := "scamshield_test_" + hex.EncodeToString(b[:])

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}

	cfg, err := pgxpool.ParseConfig(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		pool.Close()
		admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close(ctx)
	})

	for _, file := range []string{"../../ScamShield_DB.sql", "../../dev_seed.sql"} {
		sql, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}

	srv := httptest.NewServer(New(pool, "../..").Handler())
	t.Cleanup(srv.Close)
	return srv
}

type client struct {
	t   *testing.T
	srv *httptest.Server
	c   *http.Client
}

func newClient(t *testing.T, srv *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, srv: srv, c: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func (c *client) login(email string) {
	c.t.Helper()
	if code := c.do("POST", "/api/auth/login",
		map[string]string{"email": email, "password": "password123"}, nil); code != 200 {
		c.t.Fatalf("login %s: %d", email, code)
	}
}

func (c *client) submit(content string) string {
	c.t.Helper()
	var out struct{ ID string }
	if code := c.do("POST", "/api/reports",
		map[string]string{"category": "government", "content": content}, &out); code != 201 {
		c.t.Fatalf("submit: %d", code)
	}
	return out.ID
}

type myReportsResp struct {
	Reports []struct {
		ID             string
		ReportID       string
		Status         string
		Content        string
		RedactionCount int
		PublicReportID *string
		DecidedAt      *string
	}
}

func TestAuth(t *testing.T) {
	srv := newTestServer(t)
	c := newClient(t, srv)

	var me struct{ User *User }
	c.do("GET", "/api/auth/me", nil, &me)
	if me.User != nil {
		t.Fatal("signed in before login")
	}

	if code := c.do("POST", "/api/auth/login",
		map[string]string{"email": "alice@example.com", "password": "wrong"}, nil); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	c.login("ALICE@example.com")
	c.do("GET", "/api/auth/me", nil, &me)
	if me.User == nil || me.User.Email != "alice@example.com" || me.User.Role != "user" {
		t.Fatalf("me = %+v", me.User)
	}

	c.do("POST", "/api/auth/logout", nil, nil)
	me.User = nil
	c.do("GET", "/api/auth/me", nil, &me)
	if me.User != nil {
		t.Fatal("still signed in after logout")
	}
	if code := c.do("GET", "/api/my-reports", nil, nil); code != 401 {
		t.Fatalf("my-reports signed out: %d", code)
	}
}

func TestRejectsNonJSONPosts(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.PostForm(srv.URL+"/api/reports", url.Values{"content": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("form post: %d", resp.StatusCode)
	}
}

func TestReportLifecycle(t *testing.T) {
	srv := newTestServer(t)
	alice := newClient(t, srv)
	alice.login("alice@example.com")
	mod := newClient(t, srv)
	mod.login("mod@example.com")
	anon := newClient(t, srv)

	approvedSub := alice.submit("CRA called 416-555-0142 demanding gift cards")
	rejectedSub := alice.submit("Not really a scam")
	mergedSub := alice.submit("Same CRA gift card call again")
	pendingSub := alice.submit("Still waiting on this one")
	anon.submit("Anonymous CRA call")

	var mine myReportsResp
	if code := alice.do("GET", "/api/my-reports", nil, &mine); code != 200 {
		t.Fatalf("my-reports: %d", code)
	}
	if len(mine.Reports) != 4 {
		t.Fatalf("want 4 own reports, got %d", len(mine.Reports))
	}
	byID := map[string]int{}
	for i, r := range mine.Reports {
		byID[r.ID] = i
		if r.Status != "Pending" || r.PublicReportID != nil {
			t.Fatalf("new report %+v", r)
		}
	}
	if mine.Reports[0].ID != pendingSub {
		t.Fatal("not newest first")
	}
	first := mine.Reports[byID[approvedSub]]
	if strings.Contains(first.Content, "416-555-0142") || first.RedactionCount != 1 {
		t.Fatalf("phone number not redacted: %+v", first)
	}
	reportOf := func(sub string) string { return mine.Reports[byID[sub]].ReportID }

	// Pending reports are not public.
	if code := anon.do("GET", "/api/reports/"+reportOf(approvedSub), nil, nil); code != 404 {
		t.Fatalf("pending public view: %d", code)
	}

	// Only moderators can see the queue or decide.
	decide := func(c *client, sub, decision, target string) int {
		return c.do("POST", "/api/moderation/reports/"+reportOf(sub)+"/decision",
			map[string]string{"decision": decision, "mergeInto": target}, nil)
	}
	if code := alice.do("GET", "/api/moderation/queue", nil, nil); code != 403 {
		t.Fatalf("user queue: %d", code)
	}
	if code := decide(alice, approvedSub, "approve", ""); code != 403 {
		t.Fatalf("user decision: %d", code)
	}
	if code := decide(anon, approvedSub, "approve", ""); code != 401 {
		t.Fatalf("anon decision: %d", code)
	}

	var queue struct{ Queue []queueItem }
	mod.do("GET", "/api/moderation/queue", nil, &queue)
	if len(queue.Queue) != 5 {
		t.Fatalf("queue has %d items", len(queue.Queue))
	}

	// Merging into a report that isn't Approved is refused.
	if code := decide(mod, mergedSub, "merge", reportOf(pendingSub)); code != 422 {
		t.Fatalf("merge into pending: %d", code)
	}
	if code := decide(mod, mergedSub, "merge", reportOf(mergedSub)); code != 422 {
		t.Fatalf("merge into self: %d", code)
	}
	if code := decide(mod, mergedSub, "merge", "not-a-uuid"); code != 422 {
		t.Fatalf("merge into garbage: %d", code)
	}

	if code := decide(mod, approvedSub, "approve", ""); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if code := decide(mod, rejectedSub, "reject", ""); code != 200 {
		t.Fatalf("reject: %d", code)
	}
	if code := decide(mod, mergedSub, "merge", reportOf(approvedSub)); code != 200 {
		t.Fatalf("merge: %d", code)
	}
	// Decisions are final.
	if code := decide(mod, approvedSub, "reject", ""); code != 409 {
		t.Fatalf("re-decide: %d", code)
	}
	if code := mod.do("POST", "/api/moderation/reports/00000000-0000-4000-8000-000000000000/decision",
		map[string]string{"decision": "approve"}, nil); code != 404 {
		t.Fatalf("unknown report: %d", code)
	}
	if code := decide(mod, pendingSub, "publish", ""); code != 400 {
		t.Fatalf("bad decision: %d", code)
	}

	alice.do("GET", "/api/my-reports", nil, &mine)
	want := map[string]struct {
		status string
		link   string
	}{
		approvedSub: {"Approved", reportOf(approvedSub)},
		mergedSub:   {"Merged", reportOf(approvedSub)},
		rejectedSub: {"Rejected", ""},
		pendingSub:  {"Pending", ""},
	}
	for _, r := range mine.Reports {
		w := want[r.ID]
		link := ""
		if r.PublicReportID != nil {
			link = *r.PublicReportID
		}
		if r.Status != w.status || link != w.link {
			t.Errorf("%s: status %s link %q; want %s %q", r.ID, r.Status, link, w.status, w.link)
		}
		if (r.Status == "Pending") != (r.DecidedAt == nil) {
			t.Errorf("%s: decidedAt %v", r.Status, r.DecidedAt)
		}
	}

	// Public view: Approved shows itself, Merged points at its target.
	var pub struct {
		Report     *publicReport
		MergedInto string
	}
	if code := anon.do("GET", "/api/reports/"+reportOf(approvedSub), nil, &pub); code != 200 || pub.Report == nil {
		t.Fatalf("approved public view: %d %+v", code, pub)
	}
	if pub.Report.ReportCount != 2 {
		t.Fatalf("merged submission not counted: %d", pub.Report.ReportCount)
	}
	pub = struct {
		Report     *publicReport
		MergedInto string
	}{}
	anon.do("GET", "/api/reports/"+reportOf(mergedSub), nil, &pub)
	if pub.MergedInto != reportOf(approvedSub) || pub.Report != nil {
		t.Fatalf("merged public view: %+v", pub)
	}
	if code := anon.do("GET", "/api/reports/"+reportOf(rejectedSub), nil, nil); code != 404 {
		t.Fatalf("rejected public view: %d", code)
	}

	// Search only returns Approved reports.
	var search struct {
		Results []publicReport
		Total   int
	}
	anon.do("GET", "/api/reports?q=gift", nil, &search)
	if search.Total != 1 || search.Results[0].ID != reportOf(approvedSub) {
		t.Fatalf("search: %+v", search)
	}

	// Other users don't see alice's reports.
	var modMine myReportsResp
	mod.do("GET", "/api/my-reports", nil, &modMine)
	if len(modMine.Reports) != 0 {
		t.Fatalf("moderator sees %d reports", len(modMine.Reports))
	}
}

func TestSenderGrouping(t *testing.T) {
	srv := newTestServer(t)
	c := newClient(t, srv)
	c.login("alice@example.com")

	post := func(value string) int {
		return c.do("POST", "/api/reports", map[string]any{
			"category": "government", "content": "CRA call",
			"sender": map[string]string{"type": "phone", "value": value},
		}, nil)
	}
	if code := post("(416) 555-0142"); code != 201 {
		t.Fatalf("first: %d", code)
	}
	if code := post("1-416-555-0142"); code != 201 {
		t.Fatalf("second: %d", code)
	}
	if code := post("12"); code != 400 {
		t.Fatalf("bad phone: %d", code)
	}

	var mine myReportsResp
	c.do("GET", "/api/my-reports", nil, &mine)
	if len(mine.Reports) != 2 || mine.Reports[0].ReportID != mine.Reports[1].ReportID {
		t.Fatalf("same sender should share one report: %+v", mine.Reports)
	}
}

func TestNormalizeSender(t *testing.T) {
	ok := map[[2]string]string{
		{"phone", "416-555-0142"}:                       "+14165550142",
		{"phone", "+44 20 7946 0958"}:                   "+442079460958",
		{"domain", "https://WWW.Canada-Post.com/track"}: "canada-post.com",
		{"email", " Agent.CRA@Gmail.com "}:              "agent.cra@gmail.com",
	}
	for in, want := range ok {
		if got, err := normalizeSender(in[0], in[1]); err != nil || got != want {
			t.Errorf("%v = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range [][2]string{{"phone", "123"}, {"domain", "not a site"}, {"email", "a@b"}, {"fax", "1"}} {
		if _, err := normalizeSender(in[0], in[1]); err == nil {
			t.Errorf("%v accepted", in)
		}
	}
}

func TestStaticAllowlist(t *testing.T) {
	srv := newTestServer(t)
	for path, want := range map[string]int{
		"/":                          200,
		"/index.html":                200,
		"/router.js":                 200,
		"/ScamShield_DB.sql":         404,
		"/dev_seed.sql":              404,
		"/internal/redact/redact.go": 404,
		"/../go.mod":                 404,
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
}
