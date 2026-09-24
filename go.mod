module github.com/onflow/crypto

go 1.26.0

require (
	// Minimum version, not a pin: Go builds with the highest version required across the build.
	// Keeping this floor low lets consumers choose their own go-ethereum version;
	// raising it forces the new version on all of them.
	// Only raise it if this module needs something the current version lacks,
	// and audit the changes under go-ethereum/crypto/secp256k1 when doing so.
	github.com/ethereum/go-ethereum v1.17.6
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.55.0
	gonum.org/v1/gonum v0.16.0
	pgregory.net/rapid v0.4.7
)

require (
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
