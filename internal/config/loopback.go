package config

import (
	"net"
	"net/url"
	"strings"
)

// IsLoopbackHTTP reports whether raw is a plain http:// URL whose host is a
// literal loopback address (127.0.0.0/8, ::1) or "localhost". Such traffic
// never leaves the host or container network namespace, so production allows
// it for provider URLs, e.g. a co-located SMS gateway in the same container.
func IsLoopbackHTTP(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "http") || u.User != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
