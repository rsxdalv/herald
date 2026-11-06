package handlers

import "github.com/soulteary/herald/internal/config"

// testCodeSecret is a fixed 32-byte OTP code secret for tests that build a
// challenge-kit manager directly. It is also installed as the process secret so
// NewHandlers-built managers verify codes minted by those test managers.
var testCodeSecret = []byte("0123456789abcdef0123456789abcdef")

func init() { config.OTPCodeSecret = string(testCodeSecret) }
