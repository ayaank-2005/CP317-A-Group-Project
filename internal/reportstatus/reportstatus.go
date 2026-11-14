// Package reportstatus gives each submitted report a unique ID and tracks
// its review status (UI-6-T1).
//
// Only a moderator can change a report's status:
//
//	Pending --approve--> Approved
//	Pending --reject---> Rejected
//	Pending --merge----> Merged   (into a different, Approved report)
//
// Approved, Rejected and Merged are final. Pending covers both the
// 'collecting' and 'pending_review' values of scam_reports.status.
package reportstatus

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// MaxContent is the longest report text accepted, in bytes.
const MaxContent = 4000

type Status int

const (
	Pending Status = iota
	Approved
	Rejected
	Merged
)

var statusNames = [...]string{
	Pending:  "Pending",
	Approved: "Approved",
	Rejected: "Rejected",
	Merged:   "Merged",
}

// String is the label shown to users.
func (s Status) String() string {
	if s < Pending || s > Merged {
		return "Unknown"
	}
	return statusNames[s]
}

// DB is the scam_reports.status value written for s.
func (s Status) DB() string {
	switch s {
	case Pending:
		return "pending_review"
	case Approved:
		return "approved"
	case Rejected:
		return "rejected"
	case Merged:
		return "merged"
	}
	return ""
}

// FromDB maps a scam_reports.status value.
func FromDB(value string) (Status, bool) {
	switch value {
	case "collecting", "pending_review":
		return Pending, true
	case "approved":
		return Approved, true
	case "rejected":
		return Rejected, true
	case "merged":
		return Merged, true
	}
	return 0, false
}

// Role mirrors users.role.
type Role int

const (
	RoleUser Role = iota
	RoleModerator
	RoleAnalyst
)

// ParseRole maps a users.role value.
func ParseRole(value string) (Role, bool) {
	switch value {
	case "user":
		return RoleUser, true
	case "moderator":
		return RoleModerator, true
	case "analyst":
		return RoleAnalyst, true
	}
	return 0, false
}

var (
	ErrNotFound    = errors.New("report not found")
	ErrForbidden   = errors.New("only moderators can change a report's status")
	ErrTransition  = errors.New("only Pending reports can be approved, rejected or merged")
	ErrMergeTarget = errors.New("merge target must be a different, Approved report")
)

// NewID returns a random UUID v4, the same format as the schema's UUID keys.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate report id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// IsValidID reports whether id is a canonical lowercase or uppercase UUID.
func IsValidID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// MergeTarget describes the report a decision would merge into.
type MergeTarget struct {
	Found  bool
	IsSelf bool
	Status Status
}

// ValidateDecision checks a moderator decision against the transition
// rules. target is only consulted when decision is Merged.
func ValidateDecision(current Status, role Role, decision Status, target MergeTarget) error {
	if role != RoleModerator {
		return ErrForbidden
	}
	if decision != Approved && decision != Rejected && decision != Merged {
		return ErrTransition
	}
	if current != Pending {
		return ErrTransition
	}
	// Only Approved targets: they are final and public, so a merged
	// report's link can never point at a hidden page or form a chain.
	if decision == Merged && (!target.Found || target.IsSelf || target.Status != Approved) {
		return ErrMergeTarget
	}
	return nil
}

// PublicReportID is the public report to link to: the report itself when
// Approved, its merge target when Merged, and "" otherwise.
func PublicReportID(s Status, reportID, mergedIntoID string) string {
	switch s {
	case Approved:
		return reportID
	case Merged:
		return mergedIntoID
	}
	return ""
}
