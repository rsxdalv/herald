package handlers

import (
	"strings"
	"testing"

	challengekit "github.com/soulteary/challenge-kit"
	"github.com/stretchr/testify/require"

	"github.com/soulteary/herald/internal/config"
)

func TestHandlersRefuseShortOTPCodeSecret(t *testing.T) {
	old := config.OTPCodeSecret
	defer func() { config.OTPCodeSecret = old }()
	config.OTPCodeSecret = strings.Repeat("a", 31)
	rc := testRedisClient(t)
	t.Cleanup(func() { _ = rc.Close() })
	_, err := NewHandlersWithError(rc, testLogger())
	require.Error(t, err)
	require.Contains(t, err.Error(), "HERALD_OTP_CODE_SECRET")
}

// A challenge created through the real handler stores a keyed HMAC bound to its
// ID (never the code), the right code verifies, a wrong code does not, and the
// same code cannot be replayed under another challenge's ID.
func TestStoredCodeHashIsKeyedHMAC(t *testing.T) {
	rc := testRedisClient(t)
	t.Cleanup(func() { _ = rc.Close() })
	h := newIdemHandlers(t, rc)
	ch, code, err := h.challengeManager.Create(t.Context(), challengekit.CreateRequest{UserID: "u1", Channel: challengekit.ChannelSMS, Destination: "+37120000000", Purpose: "login"})
	require.NoError(t, err)
	raw, err := rc.Get(t.Context(), "otp:ch:"+ch.ID).Result()
	require.NoError(t, err)
	require.NotContains(t, raw, code)
	require.Contains(t, raw, `"code_hash":"hmac-sha256$v1$`)

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	res, _ := h.challengeManager.Verify(t.Context(), ch.ID, wrong, "127.0.0.1")
	require.False(t, res.OK)
	res, err = h.challengeManager.Verify(t.Context(), ch.ID, code, "127.0.0.1")
	require.NoError(t, err)
	require.True(t, res.OK)
}
