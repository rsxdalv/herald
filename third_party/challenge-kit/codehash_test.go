package challenge

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCodeHashRightAndWrongCode(t *testing.T) {
	mr, client := setupMiniRedis(t)
	defer mr.Close()
	m := NewManager(client, testConfig())
	ch, code, err := m.Create(context.Background(), CreateRequest{UserID: "u", Channel: "sms", Destination: "+37120000000", Purpose: "login"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ch.CodeHash, code) || !strings.HasPrefix(ch.CodeHash, "hmac-sha256$v1$") {
		t.Fatalf("bad stored hash %q", ch.CodeHash)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if res, _ := m.Verify(context.Background(), ch.ID, wrong, ""); res == nil || res.OK {
		t.Fatal("wrong code accepted")
	}
	res, err := m.Verify(context.Background(), ch.ID, code, "")
	if err != nil || !res.OK {
		t.Fatalf("right code rejected: %v %+v", err, res)
	}
	if res, _ := m.Verify(context.Background(), ch.ID, code, ""); res.OK {
		t.Fatal("code reusable after success")
	}
}

func TestCodeHashBoundToChallengeID(t *testing.T) {
	h, err := newCodeHasher(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	stored := h.hash("ch_A", "123456")
	if !h.verify("ch_A", "123456", stored) {
		t.Fatal("same id and code must verify")
	}
	if h.verify("ch_B", "123456", stored) {
		t.Fatal("hash verified under a different challenge ID")
	}
	if h.hash("ch_A", "123456") != stored {
		t.Fatal("hash must be deterministic for the same secret")
	}
	// Length prefix: shifting a character between id and code must not collide.
	if h.hash("ch_A1", "23456") == stored {
		t.Fatal("id/code boundary aliasing")
	}
}

func TestCodeHashBoundToChallengeIDEndToEnd(t *testing.T) {
	mr, client := setupMiniRedis(t)
	defer mr.Close()
	m := NewManager(client, testConfig())
	a, codeA, _ := m.Create(context.Background(), CreateRequest{UserID: "u1", Channel: "sms", Destination: "+1", Purpose: "login"})
	b, _, _ := m.Create(context.Background(), CreateRequest{UserID: "u2", Channel: "sms", Destination: "+2", Purpose: "login"})
	// Move A's stored hash into B's record: A's code must not open B.
	b.CodeHash = a.CodeHash
	if err := m.cache.Set(context.Background(), b.ID, b, m.config.Expiry); err != nil {
		t.Fatal(err)
	}
	if res, _ := m.Verify(context.Background(), b.ID, codeA, ""); res.OK {
		t.Fatal("hash copied across challenges was accepted")
	}
}

func TestCodeSecretTooShortRefused(t *testing.T) {
	for _, secret := range [][]byte{nil, {}, bytes.Repeat([]byte("a"), 31)} {
		cfg := DefaultConfig()
		cfg.CodeSecret = secret
		if err := cfg.Validate(); !errors.Is(err, ErrInvalidCodeSecret) {
			t.Fatalf("len %d: Validate = %v", len(secret), err)
		}
		mr, client := setupMiniRedis(t)
		m := NewManager(client, cfg)
		if _, _, err := m.Create(context.Background(), CreateRequest{UserID: "u"}); !errors.Is(err, ErrInvalidCodeSecret) {
			t.Fatalf("Create with short secret = %v", err)
		}
		if res, err := m.Verify(context.Background(), "ch_x", "123456", ""); err == nil || res.OK {
			t.Fatal("Verify must fail closed with a bad secret")
		}
		mr.Close()
	}
	cfg := DefaultConfig()
	cfg.CodeSecret = bytes.Repeat([]byte("a"), 32)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("32-byte secret refused: %v", err)
	}
}

func TestCodeSecretRotation(t *testing.T) {
	old := bytes.Repeat([]byte{1}, 32)
	cfgOld := DefaultConfig()
	cfgOld.CodeSecret, cfgOld.CodeSecretID = old, "k1"
	hOld, _ := newCodeHasher(cfgOld)
	stored := hOld.hash("ch_A", "123456")

	cfgNew := DefaultConfig()
	cfgNew.CodeSecret, cfgNew.CodeSecretID = bytes.Repeat([]byte{2}, 32), "k2"
	hNew, _ := newCodeHasher(cfgNew)
	if hNew.verify("ch_A", "123456", stored) {
		t.Fatal("old hash verified without the previous secret")
	}
	cfgNew.PreviousCodeSecrets = map[string][]byte{"k1": old}
	hNew, err := newCodeHasher(cfgNew)
	if err != nil {
		t.Fatal(err)
	}
	if !hNew.verify("ch_A", "123456", stored) {
		t.Fatal("old hash rejected despite previous secret")
	}
	if !strings.HasPrefix(hNew.hash("ch_A", "123456"), "hmac-sha256$k2$") {
		t.Fatal("new hashes must use the current key ID")
	}
}

func TestCodeHashRejectsMalformed(t *testing.T) {
	h, _ := newCodeHasher(testConfig())
	for _, s := range []string{"", "corrupt", "hmac-sha256$v1$", "hmac-sha256$v1$!!!", "hmac-sha256$zz$AAAA", "argon2$v1$AAAA", "a:b", "hmac-sha256$v1$AAAA$x"} {
		if h.verify("ch_A", "123456", s) {
			t.Fatalf("accepted %q", s)
		}
	}
}
