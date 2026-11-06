# Modified copy of challenge-kit

This directory is a modified copy of
[github.com/soulteary/challenge-kit](https://github.com/soulteary/challenge-kit) v1.10.4
(Apache License 2.0, see `LICENSE`). Herald uses it via a `replace` directive in `../../go.mod`.

Change: OTP codes are stored as keyed HMAC-SHA256 bound to the challenge ID
(`hmac-sha256$v1$<mac>`, see `codehash.go`) instead of an Argon2id hash. The key comes from
`Config` (Herald: `HERALD_OTP_CODE_SECRET`) and never touches Redis. This drops Herald's cost
per login from about 80–100 ms CPU and 64 MiB per hash to a few milliseconds.

To pick up a new upstream release: diff upstream v1.10.4 against the new tag and apply it here,
keeping `codehash.go` and the hasher wiring in `manager.go`.
