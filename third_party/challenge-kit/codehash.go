package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Code hashing.
//
// A 6-digit code has only 10^6 candidates, so no password hash (Argon2
// included) can protect it from an attacker who obtains the stored hash: they
// simply try every candidate. What does protect it is a secret the attacker
// does not have. The stored value is therefore a keyed HMAC-SHA256 over the
// challenge ID and the code, with a server-side secret that is configured at
// startup and never written to Redis. A Redis-only leak yields MACs that
// cannot be checked against any guess without that secret.
//
// Stored format: "hmac-sha256$<keyID>$<base64url(mac)>". The key ID selects the
// secret at verification time, which allows rotation: see Config.CodeSecretID
// and Config.PreviousCodeSecrets.

// MinCodeSecretBytes is the minimum accepted secret length.
const MinCodeSecretBytes = 32

// DefaultCodeSecretID is the key ID used when Config.CodeSecretID is empty.
const DefaultCodeSecretID = "v1"

const codeHashScheme = "hmac-sha256"

// codeMACDomain separates this MAC from any other use of the same secret.
const codeMACDomain = "challenge-kit/otp-code/v1"

// ErrInvalidCodeSecret is returned by Create/Verify (and by Config.Validate)
// when the configured secret is missing or shorter than MinCodeSecretBytes.
var ErrInvalidCodeSecret = errors.New("challenge: code secret must be at least 32 bytes")

// Validate checks the code-hashing configuration. It does not check the other
// fields, which NewManager normalises.
func (c Config) Validate() error {
	_, err := newCodeHasher(c)
	return err
}

type codeHasher struct {
	keyID   string
	secrets map[string][]byte
}

func validKeyID(id string) bool {
	return id != "" && len(id) <= 32 && !strings.ContainsAny(id, "$ \t\r\n\x00")
}

func newCodeHasher(c Config) (*codeHasher, error) {
	id := c.CodeSecretID
	if id == "" {
		id = DefaultCodeSecretID
	}
	if !validKeyID(id) {
		return nil, fmt.Errorf("challenge: invalid code secret ID")
	}
	if len(c.CodeSecret) < MinCodeSecretBytes {
		return nil, ErrInvalidCodeSecret
	}
	h := &codeHasher{keyID: id, secrets: map[string][]byte{id: append([]byte(nil), c.CodeSecret...)}}
	for pid, s := range c.PreviousCodeSecrets {
		if !validKeyID(pid) {
			return nil, fmt.Errorf("challenge: invalid previous code secret ID")
		}
		if pid == id {
			return nil, fmt.Errorf("challenge: previous code secret ID %q duplicates the current ID", pid)
		}
		if len(s) < MinCodeSecretBytes {
			return nil, ErrInvalidCodeSecret
		}
		h.secrets[pid] = append([]byte(nil), s...)
	}
	return h, nil
}

func codeMAC(secret []byte, challengeID, code string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(codeMACDomain))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(challengeID)))
	m.Write(n[:]) // length prefix: (id, code) pairs cannot alias
	m.Write([]byte(challengeID))
	m.Write([]byte(code))
	return m.Sum(nil)
}

// hash returns the storable hash of code, bound to challengeID.
func (h *codeHasher) hash(challengeID, code string) string {
	mac := codeMAC(h.secrets[h.keyID], challengeID, code)
	return codeHashScheme + "$" + h.keyID + "$" + base64.RawURLEncoding.EncodeToString(mac)
}

// verify reports whether code matches stored for challengeID, in constant time
// with respect to the MAC. Unknown schemes, unknown key IDs and malformed
// values never match.
func (h *codeHasher) verify(challengeID, code, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 3 || parts[0] != codeHashScheme {
		return false
	}
	secret, ok := h.secrets[parts[1]]
	if !ok {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(want) != sha256.Size {
		return false
	}
	return hmac.Equal(want, codeMAC(secret, challengeID, code))
}
