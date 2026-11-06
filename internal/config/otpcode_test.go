package config

import (
	"strings"
	"testing"
)

const goodOTPSecret = "otp-code-secret-0123456789abcdefghij" // 36 bytes

func withOTPSecretState(t *testing.T) {
	t.Helper()
	s, id, prev, gen := OTPCodeSecret, OTPCodeSecretID, OTPCodeSecretsPreviousJSON, otpCodeSecretGenerated
	hm, pp, ip, api, env := HMACSecret, PIIPepper, IdempotencySecret, APIKey, Env
	t.Cleanup(func() {
		OTPCodeSecret, OTPCodeSecretID, OTPCodeSecretsPreviousJSON, otpCodeSecretGenerated = s, id, prev, gen
		HMACSecret, PIIPepper, IdempotencySecret, APIKey, Env = hm, pp, ip, api, env
	})
}

func hasProblem(problems []string, sub string) bool {
	for _, p := range problems {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func TestOTPCodeSecretRequiredInProduction(t *testing.T) {
	withOTPSecretState(t)
	OTPCodeSecret = ""
	if !hasProblem(otpCodeSecretProblems(true), "HERALD_OTP_CODE_SECRET is required in production") {
		t.Fatal("production must require HERALD_OTP_CODE_SECRET")
	}
	if len(otpCodeSecretProblems(false)) != 0 {
		t.Fatal("non-production must not require it")
	}
	OTPCodeSecret = goodOTPSecret
	HMACSecret, PIIPepper, IdempotencySecret, APIKey = "h-"+goodOTPSecret, "p-"+goodOTPSecret, "i-"+goodOTPSecret, ""
	if p := otpCodeSecretProblems(true); len(p) != 0 {
		t.Fatalf("valid production secret rejected: %v", p)
	}
}

func TestOTPCodeSecretValidateWiresProduction(t *testing.T) {
	withOTPSecretState(t)
	Env = EnvProduction
	OTPCodeSecret = ""
	err := Validate()
	if err == nil || !strings.Contains(err.Error(), "HERALD_OTP_CODE_SECRET") {
		t.Fatalf("Validate() in production without the secret = %v", err)
	}
}

func TestOTPCodeSecretShortRefused(t *testing.T) {
	withOTPSecretState(t)
	OTPCodeSecret = strings.Repeat("a", 31)
	if !hasProblem(otpCodeSecretProblems(true), "at least 32 bytes") || !hasProblem(otpCodeSecretProblems(false), "at least 32 bytes") {
		t.Fatal("31-byte secret must be refused in every environment")
	}
	Env = EnvDevelopment
	if err := initializeOTPCodeSecret(); err == nil {
		t.Fatal("startup must fail for a short configured secret, even outside production")
	}
}

func TestOTPCodeSecretMustDifferFromOtherSecrets(t *testing.T) {
	for name, set := range map[string]func(){
		"HMAC_SECRET":               func() { HMACSecret = goodOTPSecret },
		"HERALD_PII_PEPPER":         func() { PIIPepper = goodOTPSecret },
		"HERALD_IDEMPOTENCY_SECRET": func() { IdempotencySecret = goodOTPSecret },
		"API_KEY":                   func() { APIKey = goodOTPSecret },
	} {
		t.Run(name, func(t *testing.T) {
			withOTPSecretState(t)
			OTPCodeSecret = goodOTPSecret
			HMACSecret, PIIPepper, IdempotencySecret, APIKey = "", "", "", ""
			set()
			if !hasProblem(otpCodeSecretProblems(true), "must differ from "+name) {
				t.Fatalf("reuse of %s not rejected", name)
			}
		})
	}
}

func TestOTPCodeSecretGeneratedOutsideProduction(t *testing.T) {
	withOTPSecretState(t)
	Env = EnvDevelopment
	OTPCodeSecret, otpCodeSecretGenerated = "", false
	if err := initializeOTPCodeSecret(); err != nil {
		t.Fatal(err)
	}
	if len([]byte(OTPCodeSecret)) < 32 || !OTPCodeSecretGenerated() {
		t.Fatalf("expected a generated >=32-byte secret, got %d bytes", len(OTPCodeSecret))
	}
	first := OTPCodeSecret
	if err := initializeOTPCodeSecret(); err != nil || OTPCodeSecret != first {
		t.Fatal("generation must be idempotent")
	}
	Env = EnvProduction
	OTPCodeSecret = ""
	if err := initializeOTPCodeSecret(); err != nil || OTPCodeSecret != "" {
		t.Fatal("production must never auto-generate")
	}
}

func TestOTPCodePreviousSecretsParsing(t *testing.T) {
	withOTPSecretState(t)
	OTPCodeSecretsPreviousJSON = `{"k1":"` + goodOTPSecret + `"}`
	m, err := OTPCodePreviousSecrets()
	if err != nil || string(m["k1"]) != goodOTPSecret {
		t.Fatalf("parse: %v %v", m, err)
	}
	for _, bad := range []string{`not json`, `{"k1":"short"}`, `{"a$b":"` + goodOTPSecret + `"}`} {
		OTPCodeSecretsPreviousJSON = bad
		if _, err := OTPCodePreviousSecrets(); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
