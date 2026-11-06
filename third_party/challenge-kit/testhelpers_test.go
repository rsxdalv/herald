package challenge

import "bytes"

// testCodeSecret is a fixed 32-byte test secret.
var testCodeSecret = bytes.Repeat([]byte{0x5a}, 32)

// testConfig is DefaultConfig plus the (required) code secret.
func testConfig() Config {
	c := DefaultConfig()
	c.CodeSecret = testCodeSecret
	return c
}
