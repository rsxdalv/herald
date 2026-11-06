package config

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/soulteary/cli-kit/env"
)

// minOTPCodeSecretBytes mirrors challenge-kit's MinCodeSecretBytes.
const minOTPCodeSecretBytes = 32

var (
	// OTPCodeSecret keys the HMAC-SHA256 that protects stored OTP codes. It is
	// never written to Redis. Required in production (>= 32 bytes, distinct
	// from every other Herald secret). Outside production an unset value is
	// replaced by a random per-process secret (see initializeOTPCodeSecret).
	OTPCodeSecret = env.Get("HERALD_OTP_CODE_SECRET", "")
	// OTPCodeSecretID labels OTPCodeSecret inside stored hashes (default "v1").
	// Change it together with the secret when rotating.
	OTPCodeSecretID = env.Get("HERALD_OTP_CODE_SECRET_ID", "")
	// OTPCodeSecretsPreviousJSON optionally lists retired secrets that are
	// still accepted for verification during rotation, as {"<id>":"<secret>"}.
	OTPCodeSecretsPreviousJSON = env.Get("HERALD_OTP_CODE_SECRETS_PREVIOUS", "")

	otpCodeSecretGenerated bool
)

// OTPCodeSecretBytes returns the secret for challenge-kit.
func OTPCodeSecretBytes() []byte { return []byte(OTPCodeSecret) }

// OTPCodeSecretGenerated reports whether the secret was randomly generated at
// startup (codes then do not survive a restart or work across instances).
func OTPCodeSecretGenerated() bool { return otpCodeSecretGenerated }

// OTPCodePreviousSecrets returns the parsed retired secrets (nil if none).
func OTPCodePreviousSecrets() (map[string][]byte, error) {
	if strings.TrimSpace(OTPCodeSecretsPreviousJSON) == "" {
		return nil, nil
	}
	var raw map[string]string
	if err := json.Unmarshal([]byte(OTPCodeSecretsPreviousJSON), &raw); err != nil {
		return nil, fmt.Errorf("HERALD_OTP_CODE_SECRETS_PREVIOUS must be a JSON object of id to secret")
	}
	out := make(map[string][]byte, len(raw))
	for id, s := range raw {
		if id == "" || strings.ContainsAny(id, "$ \t\r\n") {
			return nil, fmt.Errorf("HERALD_OTP_CODE_SECRETS_PREVIOUS contains an invalid key ID")
		}
		if len([]byte(s)) < minOTPCodeSecretBytes {
			return nil, fmt.Errorf("HERALD_OTP_CODE_SECRETS_PREVIOUS[%q] must be at least %d bytes", id, minOTPCodeSecretBytes)
		}
		out[id] = []byte(s)
	}
	return out, nil
}

// initializeOTPCodeSecret generates a random secret outside production when
// none is configured. In production an unset secret is left empty and rejected
// by Validate.
// InitializeOTPCodeSecret is idempotent; handlers call it so that callers that
// skip config.Initialize still get a secret outside production.
func InitializeOTPCodeSecret() error { return initializeOTPCodeSecret() }

func initializeOTPCodeSecret() error {
	if OTPCodeSecret != "" {
		// Fatal in every environment: a short secret would make challenge-kit
		// refuse every Create/Verify at runtime.
		if len([]byte(OTPCodeSecret)) < minOTPCodeSecretBytes {
			return fmt.Errorf("HERALD_OTP_CODE_SECRET must be at least %d bytes", minOTPCodeSecretBytes)
		}
		return nil
	}
	if Env == EnvProduction {
		return nil
	}
	buf := make([]byte, minOTPCodeSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("generate HERALD_OTP_CODE_SECRET: %w", err)
	}
	OTPCodeSecret = hex.EncodeToString(buf)
	otpCodeSecretGenerated = true
	if log != nil {
		log.Warn().Msg("HERALD_OTP_CODE_SECRET is not set: generated a random per-process secret; OTP codes will not survive a restart or work across instances (required in production)")
	}
	return nil
}

// otpCodeSecretProblems returns configuration problems for the OTP code
// secret. A configured secret is always length-checked; the production-only
// requirements are presence and distinctness from every other Herald secret
// (a leak of one must not unlock the others).
func otpCodeSecretProblems(production bool) []string {
	var problems []string
	if OTPCodeSecret == "" {
		if production {
			problems = append(problems, fmt.Sprintf("HERALD_OTP_CODE_SECRET is required in production (at least %d bytes)", minOTPCodeSecretBytes))
		}
		return problems
	}
	if len([]byte(OTPCodeSecret)) < minOTPCodeSecretBytes {
		problems = append(problems, fmt.Sprintf("HERALD_OTP_CODE_SECRET must be at least %d bytes", minOTPCodeSecretBytes))
	}
	if _, err := OTPCodePreviousSecrets(); err != nil {
		problems = append(problems, err.Error())
	}
	if production {
		same := func(name, other string) {
			if other != "" && subtle.ConstantTimeCompare([]byte(OTPCodeSecret), []byte(other)) == 1 {
				problems = append(problems, "HERALD_OTP_CODE_SECRET must differ from "+name)
			}
		}
		same("HMAC_SECRET", HMACSecret)
		same("HERALD_PII_PEPPER", PIIPepper)
		same("HERALD_IDEMPOTENCY_SECRET", IdempotencySecret)
		same("API_KEY", APIKey)
		same("HERALD_TOTP_HMAC_SECRET", TOTPHMACSecret)
		for keyID, secret := range hmacKeysMap {
			same(fmt.Sprintf("HERALD_HMAC_KEYS[%q]", keyID), secret)
		}
	}
	return problems
}
