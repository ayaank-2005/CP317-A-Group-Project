// internal/moderation/access.go
// Keeps the review routes private while there are no user accounts.
//
// A moderator enters a secret access key on the Review page. The page sends it in an
// X-Mod-Key header with every request, and this guard compares it with the MOD_ACCESS_KEY
// environment variable. If the variable is missing or too short the routes stay switched OFF,
// so a forgotten setting can never leave them open.
//
// This is a stop-gap. When sign-up and login are added, replace RequireKey with
// auth.RequireRole(..., "moderator") and the rest of the package does not change.
package moderation

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"os"
	"time"
)

const (
	keyEnv    = "MOD_ACCESS_KEY"
	keyHeader = "X-Mod-Key"
	minKeyLen = 24 // long enough that guessing it is not realistic
)

// envKey is where the real key comes from. Tests replace it.
var envKey = func() string { return os.Getenv(keyEnv) }

// failDelay slows down repeated wrong guesses a little. Tests set it to zero.
var failDelay = 400 * time.Millisecond

// RequireKey wraps a handler so only requests with the right access key reach it.
//
//	keyed := moderation.RequireKey
//	queueHandler = keyed(moderation.ReviewQueue(openMod))
func RequireKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := envKey()
		if len(key) < minKeyLen {
			writeError(w, http.StatusServiceUnavailable,
				"Report review is not switched on for this site. Ask the site owner to set "+keyEnv+".")
			return
		}

		given := r.Header.Get(keyHeader)
		if given == "" {
			writeError(w, http.StatusUnauthorized, "Enter the moderator access key.")
			return
		}

		// compare fixed-length hashes in constant time, so the reply time reveals nothing about the key
		a, b := sha256.Sum256([]byte(given)), sha256.Sum256([]byte(key))
		if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
			time.Sleep(failDelay)
			writeError(w, http.StatusUnauthorized, "That access key isn't right.")
			return
		}

		next(w, r)
	}
}
