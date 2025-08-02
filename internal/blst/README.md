This package simulates the BLST Go bindings https://github.com/supranational/blst/tree/master/bindings/go.

Files in this folder are copied from the BLST Go binding, specifically from the BLST version supported by the Flow crypto
(check https://github.com/onflow/crypto/blob/main/blst_src/README.md for the exact BLST version tag).

 Copyright Supranational LLC
 Licensed under the Apache License, Version 2.0, see LICENSE for details.
 SPDX-License-Identifier: Apache-2.0

The BLST Go bindings are not exported or used by the Flow crypto package. 
Some BLS signature bindings are used only for compatibility tests in https://github.com/onflow/crypto/blob/main/bls_crossBLST_test.go.
The BLST source code used by Flow crypto is the low level BLS12-381 arithmetic as explained in https://github.com/onflow/crypto/blob/main/blst_src/README.md. The higher level protocols using curve BLS12-381 are implemented within Flow crypto.

The reason of not importing the BLST Go bindings package but rather duplicating it as an internal package is related to a cgo build limitation. When importing the BLST Go bindings, the low level C and assembly functions are also linked when the tests are run. The cgo linker detects duplications in low level symbols (the ones from the imported BLST package and the ones from Flow crypto) and errors. By avoiding the Go package import and instead copying the BLST go bindings, the tests use the same non-duplicated low level layer for both the BLST bindings and Flow crypto. The tests are still relevant because they check compatibility of the higher layers.

