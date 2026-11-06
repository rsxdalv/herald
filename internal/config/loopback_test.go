package config

import "testing"

func TestIsLoopbackHTTP(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://127.0.0.1:8090":          true,
		"http://127.1.2.3":               true,
		"http://[::1]:8090/":             true,
		"http://localhost:8090":          true,
		"HTTP://LOCALHOST:8090":          true,
		"https://127.0.0.1:8090":         false, // https is handled by the caller
		"http://10.0.0.5:8090":           false,
		"http://sms-gateway:8090":        false,
		"http://localhost.evil.com:8090": false,
		"http://127.0.0.1.nip.io":        false,
		"http://user:pw@127.0.0.1:8090":  false,
		"ftp://127.0.0.1":                false,
		"::not a url":                    false,
	} {
		if got := IsLoopbackHTTP(raw); got != want {
			t.Errorf("IsLoopbackHTTP(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestProviderTransportAllowsLoopbackHTTPOnly(t *testing.T) {
	old := SMSAPIBaseURL
	t.Cleanup(func() { SMSAPIBaseURL = old })

	SMSAPIBaseURL = "http://127.0.0.1:8090"
	for _, p := range providerTransportProblems() {
		t.Fatalf("loopback http rejected: %s", p)
	}
	SMSAPIBaseURL = "http://sms-gateway:8090"
	if len(providerTransportProblems()) == 0 {
		t.Fatal("non-loopback http accepted")
	}
}
