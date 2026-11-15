package reportstatus

import (
	"errors"
	"testing"
)

func TestNewID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if !IsValidID(id) || id[14] != '4' || !(id[19] == '8' || id[19] == '9' || id[19] == 'a' || id[19] == 'b') {
			t.Fatalf("not a UUID v4: %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestIsValidID(t *testing.T) {
	for _, id := range []string{
		"",
		"not-an-id",
		"1; DROP TABLE users",
		"zzzzzzzz-zzzz-4zzz-8zzz-zzzzzzzzzzzz",
		"00000000-0000-4000-8000-0000000000000",
		"00000000_0000-4000-8000-000000000000",
	} {
		if IsValidID(id) {
			t.Errorf("IsValidID(%q) = true", id)
		}
	}
	if !IsValidID("2F1C0A9E-0000-4000-8000-00000000ABCD") {
		t.Error("rejected an uppercase UUID")
	}
}

func TestDBMapping(t *testing.T) {
	cases := map[string]Status{
		"collecting":     Pending,
		"pending_review": Pending,
		"approved":       Approved,
		"rejected":       Rejected,
		"merged":         Merged,
	}
	for db, want := range cases {
		if got, ok := FromDB(db); !ok || got != want {
			t.Errorf("FromDB(%q) = %v, %v; want %v", db, got, ok, want)
		}
	}
	for _, bad := range []string{"", "Approved", "bogus"} {
		if _, ok := FromDB(bad); ok {
			t.Errorf("FromDB(%q) accepted", bad)
		}
	}
	for s := Pending; s <= Merged; s++ {
		if got, ok := FromDB(s.DB()); !ok || got != s {
			t.Errorf("round trip %v: got %v", s, got)
		}
	}
	if Merged.String() != "Merged" || Status(42).String() != "Unknown" {
		t.Error("String() labels wrong")
	}
}

func TestValidateDecision(t *testing.T) {
	approvedTarget := MergeTarget{Found: true, Status: Approved}

	for _, d := range []Status{Approved, Rejected} {
		if err := ValidateDecision(Pending, RoleModerator, d, MergeTarget{}); err != nil {
			t.Errorf("%v: %v", d, err)
		}
	}
	if err := ValidateDecision(Pending, RoleModerator, Merged, approvedTarget); err != nil {
		t.Errorf("merge: %v", err)
	}

	cases := []struct {
		name     string
		current  Status
		role     Role
		decision Status
		target   MergeTarget
		want     error
	}{
		{"user cannot decide", Pending, RoleUser, Approved, MergeTarget{}, ErrForbidden},
		{"analyst cannot decide", Pending, RoleAnalyst, Rejected, MergeTarget{}, ErrForbidden},
		{"cannot decide Pending", Pending, RoleModerator, Pending, MergeTarget{}, ErrTransition},
		{"unknown decision", Pending, RoleModerator, Status(42), MergeTarget{}, ErrTransition},
		{"missing target", Pending, RoleModerator, Merged, MergeTarget{}, ErrMergeTarget},
		{"self target", Pending, RoleModerator, Merged, MergeTarget{Found: true, IsSelf: true, Status: Approved}, ErrMergeTarget},
		{"pending target", Pending, RoleModerator, Merged, MergeTarget{Found: true, Status: Pending}, ErrMergeTarget},
		{"rejected target", Pending, RoleModerator, Merged, MergeTarget{Found: true, Status: Rejected}, ErrMergeTarget},
		{"merged target", Pending, RoleModerator, Merged, MergeTarget{Found: true, Status: Merged}, ErrMergeTarget},
	}
	// Every decided status is final, whatever the next decision.
	for _, from := range []Status{Approved, Rejected, Merged} {
		for _, to := range []Status{Approved, Rejected, Merged} {
			cases = append(cases, struct {
				name     string
				current  Status
				role     Role
				decision Status
				target   MergeTarget
				want     error
			}{from.String() + " is final", from, RoleModerator, to, approvedTarget, ErrTransition})
		}
	}

	for _, c := range cases {
		if err := ValidateDecision(c.current, c.role, c.decision, c.target); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestPublicReportID(t *testing.T) {
	cases := []struct {
		status Status
		want   string
	}{
		{Approved, "self"},
		{Merged, "target"},
		{Pending, ""},
		{Rejected, ""},
	}
	for _, c := range cases {
		if got := PublicReportID(c.status, "self", "target"); got != c.want {
			t.Errorf("%v: got %q, want %q", c.status, got, c.want)
		}
	}
}

func TestParseRole(t *testing.T) {
	for value, want := range map[string]Role{"user": RoleUser, "moderator": RoleModerator, "analyst": RoleAnalyst} {
		if got, ok := ParseRole(value); !ok || got != want {
			t.Errorf("ParseRole(%q) = %v, %v", value, got, ok)
		}
	}
	if _, ok := ParseRole("admin"); ok {
		t.Error("accepted admin")
	}
}
