module github.com/minpeter/global-egress

go 1.25.12

require golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446

require github.com/BurntSushi/toml v1.6.0

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	// Pinned by wireguard-go, and deliberately not bumped: newer gvisor snapshots
	// have a broken pkg/tcpip/stack directory that declares two packages, so the
	// build fails. Let wireguard-go set this version.
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)
