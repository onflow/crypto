module github.com/onflow/crypto

go 1.26.0

require (
	github.com/ethereum/go-ethereum v1.16.8
	// fixed at this version because flow-go uses this version and Go modules does not allow
	// multiple versions of the same module.
	// This will be updated once flow-go updates to a newer version of go-ethereum.
	// Updates must audit the code changes under github.com/ethereum/go-ethereum/crypto/secp256k1 between the old and new version.
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.54.0
	gonum.org/v1/gonum v0.16.0
	pgregory.net/rapid v0.4.7
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
