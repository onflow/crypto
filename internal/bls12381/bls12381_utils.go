//go:build cgo && !no_cgo
// +build cgo,!no_cgo

/*
 * Flow Crypto
 *
 * Copyright Flow Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package crypto

// this file contains utility functions for the curve BLS 12-381
// these tools are shared by the BLS signature scheme, the BLS based threshold signature
// and the BLS distributed key generation protocols

// #cgo CFLAGS: -I${SRCDIR}/ -I${SRCDIR}/blst_src -I${SRCDIR}/blst_src/build -D__BLST_CGO__ -Wall -fno-builtin-memcpy -fno-builtin-memset -Wno-unused-function -Wno-unused-macros -Wno-unused-variable
// #cgo amd64 CFLAGS: -D__ADX__ -mno-avx
// #cgo loong64 mips64 mips64le ppc64 ppc64le riscv64 s390x CFLAGS: -D__BLST_NO_ASM__
// #cgo noescape E2_read_bytes
// #cgo nocallback E2_read_bytes
// #cgo noescape E2_write_bytes
// #cgo nocallback E2_write_bytes
// #cgo noescape E1_read_bytes
// #cgo nocallback E1_read_bytes
// #cgo noescape E1_write_bytes
// #cgo nocallback E1_write_bytes
// #cgo noescape Fr_star_read_bytes
// #cgo nocallback Fr_star_read_bytes
// #include "bls12381_utils.h"
//
// #if defined(__x86_64__) && (defined(__unix__) || defined(__APPLE__))
// # include <signal.h>
// # include <unistd.h>
// # include <string.h>
// static void handler(int signum)
// {	char text[1024] = "Caught SIGILL in flow_crypto_cgo_init, the BLST library (used by onflow/crypto) requires ADX support, build with CGO_CFLAGS=\"-O2 -D__BLST_PORTABLE__\" to disable ADX code.\n";
//		ssize_t n = write(2, &text, strlen(text));
//      _exit(128+SIGILL);
//      (void)n;
// }
// __attribute__((constructor)) static void flow_crypto_cgo_init()
// {   Fp temp = { 0 };
//     struct sigaction act = {{ handler }}, oact;
//     sigaction(SIGILL, &act, &oact);
//     Fp_squ_montg(&temp, &temp);
//     sigaction(SIGILL, &oact, NULL);
// }
// #endif
//
import "C"
import (
	"errors"
	"fmt"

	"github.com/onflow/crypto/internal"
	"github.com/onflow/crypto/random"
)

// Go wrappers around BLST C types
type PointE1 C.E1
type PointE2 C.E2
type Scalar C.Fr

// Note that scalars and field elements F_r are represented in Go by the same type
// called `scalar`, which is internally represented by C type `Fr`. Scalars used by the
// Go layer are all reduced modulo the curve order `r`.

const (
	// BLS12-381 related lengths imported from the C layer
	FrBytesLen = int(C.Fr_BYTES)
	FpBytesLen = int(C.Fp_BYTES)
	G1BytesLen = int(C.G1_SER_BYTES)
	G2BytesLen = int(C.G2_SER_BYTES)

	// error constants imported from the C layer
	Valid           = C.VALID
	Invalid         = C.INVALID
	BadEncoding     = C.BAD_ENCODING
	BadValue        = C.BAD_VALUE
	PointNotOnCurve = C.POINT_NOT_ON_CURVE

	// expandMsgOutput is the output length of the expand_message step as required by the
	// hash_to_curve algorithm (and the map to G1 step).
	ExpandMsgOutput = int(C.MAP_TO_G1_INPUT_LEN)
)

var BLS12381Order = []byte{0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39,
	0xD8, 0x08, 0x09, 0xA1, 0xD8, 0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE,
	0x5B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01}

// header of the point at infinity serializations
var g1SerHeader byte // g1 (G1 identity)
var g2SerHeader byte // g2 (G2 identity)

// `g1` serialization
var G1Serialization []byte

// initialization of BLS12-381 curve
func init() {
	C.types_sanity()

	if IsG1Compressed() {
		g1SerHeader = 0xC0
	} else {
		g1SerHeader = 0x40
	}
	G1Serialization = append([]byte{g1SerHeader}, make([]byte, G1BytesLen-1)...)
	if IsG2Compressed() {
		g2SerHeader = 0xC0
	} else {
		g2SerHeader = 0x40
	}
}

// String returns a hex-encoded representation of the scalar.
func (a *Scalar) String() string {
	encoding := make([]byte, FrBytesLen)
	WriteScalar(encoding, a)
	return fmt.Sprintf("%#x", encoding)
}

// String returns a hex-encoded representation of the E2 point.
func (p *PointE2) String() string {
	encoding := make([]byte, G2BytesLen)
	WritePointE2(encoding, p)
	return fmt.Sprintf("%#x", encoding)
}

// Scalar multiplication of a generic point `p` in E1
func (p *PointE1) ScalarMultE1(res *PointE1, expo *Scalar) {
	C.E1_mult((*C.E1)(res), (*C.E1)(p), (*C.Fr)(expo))
}

// Scalar multiplication of generator g1 in G1
func GeneratorScalarMultG1(res *PointE1, expo *Scalar) {
	C.G1_mult_gen((*C.E1)(res), (*C.Fr)(expo))
}

// Scalar multiplication of generator g2 in G2
//
// This often results in a public key that is used in
// multiple pairing computation. Therefore, convert the
// resulting point to affine coordinate to save pre-pairing
// conversions.
func GeneratorScalarMultG2(res *PointE2, expo *Scalar) {
	C.G2_mult_gen_to_affine((*C.E2)(res), (*C.Fr)(expo))
}

// comparison in F_r where r is the group order of G1/G2
// (both scalars should be reduced mod r)
func (x *Scalar) Equals(other *Scalar) bool {
	return bool(C.Fr_is_equal((*C.Fr)(x), (*C.Fr)(other)))
}

// comparison in E1
func (p *PointE1) Equals(other *PointE1) bool {
	return bool(C.E1_is_equal((*C.E1)(p), (*C.E1)(other)))
}

// comparison in E2
func (p *PointE2) Equals(other *PointE2) bool {
	return bool(C.E2_is_equal((*C.E2)(p), (*C.E2)(other)))
}

// Comparison to zero in F_r.
// Scalar must be already reduced modulo r
func (x *Scalar) IsZero() bool {
	return bool(C.Fr_is_zero((*C.Fr)(x)))
}

// Comparison to point at infinity in G2.
func (p *PointE2) IsInfinity() bool {
	return bool(C.E2_is_infty((*C.E2)(p)))
}

// Comparison to point at infinity in G2.
func (p *PointE2) SetInfinity() {
	C.E2_set_infty((*C.E2)(p))
}

// generates a random element in F_r using input random source,
// and saves the random in `x`.
// returns `true` if generated element is zero.
func RandFr(x *Scalar, rand random.Rand) bool {
	// use extra 128 bits to reduce the modular reduction bias
	bytes := make([]byte, FrBytesLen+internal.SecurityBits/8)
	rand.Read(bytes)
	// modular reduction
	return MapToFr(x, bytes)
}

// generates a random element in F_r* using input random source,
// and saves the random in `x`.
func RandFrStar(x *Scalar, rand random.Rand) {
	isZero := true
	// extremely unlikely this loop runs more than once,
	// but force the output to be non-zero instead of propagating an error.
	for isZero {
		isZero = RandFr(x, rand)
	}
}

// mapToFr reads a scalar from a slice of bytes and maps it to Fr using modular reduction.
// The resulting element `k` therefore satisfies 0 <= k < r.
// It returns true if scalar is zero and false otherwise.
func MapToFr(x *Scalar, src []byte) bool {
	isZero := C.map_bytes_to_Fr((*C.Fr)(x),
		(*C.uchar)(&src[0]),
		(C.int)(len(src)))
	return bool(isZero)
}

// writeScalar writes a scalar in a slice of bytes
func WriteScalar(dest []byte, x *Scalar) {
	C.Fr_write_bytes((*C.uchar)(&dest[0]), (*C.Fr)(x))
}

// encode returns a byte encoding of the scalar.
// The encoding is a raw encoding in big endian padded to the group order
func (x *Scalar) Encode() []byte {
	dest := make([]byte, FrBytesLen)
	WriteScalar(dest, x)
	return dest
}

// writePointE2 writes a G2 point in a slice of bytes
// The slice should be of size g2BytesLen and the serialization
// follows the Zcash format specified in draft-irtf-cfrg-pairing-friendly-curves
func WritePointE2(dest []byte, a *PointE2) {
	C.E2_write_bytes((*C.uchar)(&dest[0]), (*C.E2)(a))
}

// encode returns a byte encoding of the scalar.
// The encoding is a raw encoding in big endian padded to the group order
func (a *PointE2) Encode() []byte {
	dest := make([]byte, G2BytesLen)
	WritePointE2(dest, a)
	return dest
}

// writePointE1 writes a G1 point in a slice of bytes
// The slice should be of size g1BytesLen and the serialization
// follows the Zcash format specified in draft-irtf-cfrg-pairing-friendly-curves
func WritePointE1(dest []byte, a *PointE1) {
	C.E1_write_bytes((*C.uchar)(&dest[0]), (*C.E1)(a))
}

// read an F_r* element from a byte slice
// and stores it into a `scalar` type element.
func ReadScalarFrStar(a *Scalar, src []byte) error {
	read := C.Fr_star_read_bytes(
		(*C.Fr)(a),
		(*C.uchar)(&src[0]),
		(C.int)(len(src)))

	switch read {
	case Valid:
		return nil
	case BadEncoding:
		return internal.InvalidInputsErrorf("input length must be %d, got %d",
			FrBytesLen, len(src))
	case BadValue:
		return internal.InvalidInputsErrorf("scalar is not in the correct range")
	default:
		return internal.InvalidInputsErrorf("reading the scalar failed")
	}
}

// readPointE2 reads a E2 point from a slice of bytes
// The slice is expected to be of size g2BytesLen and the deserialization
// follows the Zcash format specified in draft-irtf-cfrg-pairing-friendly-curves.
// No G2 membership check is performed.
func ReadPointE2(a *PointE2, src []byte) error {
	read := C.E2_read_bytes((*C.E2)(a),
		(*C.uchar)(&src[0]),
		(C.int)(len(src)))

	switch read {
	case Valid:
		return nil
	case BadEncoding, BadValue:
		return internal.InvalidInputsErrorf("input could not deserialize to an E2 point")
	case PointNotOnCurve:
		return internal.InvalidInputsErrorf("input is not a point on curve E2")
	default:
		return errors.New("reading E2 point failed")
	}
}

// readPointE1 reads a E1 point from a slice of bytes
// The slice should be of size g1BytesLen and the deserialization
// follows the Zcash format specified in draft-irtf-cfrg-pairing-friendly-curves.
// No G1 membership check is performed.
func ReadPointE1(a *PointE1, src []byte) error {
	read := C.E1_read_bytes((*C.E1)(a),
		(*C.uchar)(&src[0]),
		(C.int)(len(src)))

	switch read {
	case Valid:
		return nil
	case BadEncoding, BadValue:
		return internal.InvalidInputsErrorf("input could not deserialize to a E1 point")
	case PointNotOnCurve:
		return internal.InvalidInputsErrorf("input is not a point on curve E1")
	default:
		return errors.New("reading E1 point failed")
	}
}

// CheckMembershipG1 checks if input E1 point is on the subgroup G1.
// It assumes input `p` is on E1.
func (pt *PointE1) CheckMembershipG1() bool {
	return bool(C.E1_in_G1((*C.E1)(pt)))
}

// CheckMembershipG2 checks if input E2 point is on the subgroup G2.
// It assumes input `p` is on E2.
func (pt *PointE2) CheckMembershipG2() bool {
	return bool(C.E2_in_G2((*C.E2)(pt)))
}

// This is only a TEST/DEBUG/BENCH function.
// It returns the hash-to-G1 point from a slice of 128 bytes
func MapToG1(data []byte) *PointE1 {
	l := len(data)
	var h PointE1
	if C.map_to_G1((*C.E1)(&h), (*C.uchar)(&data[0]), (C.int)(l)) != Valid {
		return nil
	}
	return &h
}

// mapToG1 is a test function, it wraps a call to C since cgo can't be used in go test files.
// It maps input bytes to a point in G2 and stores it in input point.
// THIS IS NOT the kind of mapping function that is used in BLS signature.
func unsafeMapToG1(pt *PointE1, seed []byte) {
	C.unsafe_map_bytes_to_G1((*C.E1)(pt), (*C.uchar)(&seed[0]), (C.int)(len(seed)))
}

// unsafeMapToG1Complement is a test function, it wraps a call to C since cgo can't be used in go test files.
// It generates a random point in E2\G2 and stores it in input point.
func UnsafeMapToG1Complement(pt *PointE1, seed []byte) {
	C.unsafe_map_bytes_to_G1complement((*C.E1)(pt), (*C.uchar)(&seed[0]), (C.int)(len(seed)))
}

// unsafeMapToG2 is a test function, it wraps a call to C since cgo can't be used in go test files.
// It maps input bytes to a point in G2 and stores it in input point.
// THIS IS NOT the kind of mapping function that is used in BLS signature.
func unsafeMapToG2(pt *PointE2, seed []byte) {
	C.unsafe_map_bytes_to_G2((*C.E2)(pt), (*C.uchar)(&seed[0]), (C.int)(len(seed)))
}

// unsafeMapToG2Complement is a test function, it wraps a call to C since cgo can't be used in go test files.
// It generates a random point in E2\G2 and stores it in input point.
func unsafeMapToG2Complement(pt *PointE2, seed []byte) {
	C.unsafe_map_bytes_to_G2complement((*C.E2)(pt), (*C.uchar)(&seed[0]), (C.int)(len(seed)))
}

// This is only a TEST function.
// It hashes `data` to a G1 point using the tag `dst` and returns the G1 point serialization.
// The function uses xmd with SHA256 in the hash-to-field.
func hashToG1Bytes(data, dst []byte) []byte {
	hash := make([]byte, ExpandMsgOutput)

	inputLength := len(data)
	if len(data) == 0 {
		data = make([]byte, 1)
	}

	// XMD using SHA256
	C.xmd_sha256((*C.uchar)(&hash[0]),
		(C.int)(ExpandMsgOutput),
		(*C.uchar)(&data[0]), (C.int)(inputLength),
		(*C.uchar)(&dst[0]), (C.int)(len(dst)))

	// map the hash to G1
	var point PointE1
	if C.map_to_G1((*C.E1)(&point), (*C.uchar)(&hash[0]), (C.int)(len(hash))) != Valid {
		return nil
	}

	// serialize the point
	pointBytes := make([]byte, G1BytesLen)
	WritePointE1(pointBytes, &point)
	return pointBytes
}

func IsG1Compressed() bool {
	return G1BytesLen == FpBytesLen
}

func IsG2Compressed() bool {
	return G2BytesLen == 2*FpBytesLen
}

// This is only a TEST function used to bench the package pairing
// It assumes E1 and E2 inputs are in G1 and G2 respectively, and have the same length.
func multiPairing(p1 []PointE1, p2 []PointE2) {
	var res C.Fp12
	_ = C.Fp12_multi_pairing(&res, (*C.E1)(&p1[0]), (*C.E2)(&p2[0]), (C.int)(len(p1)))
}

// Addition in E1, used in benchmark
func addE1(res *PointE1, p1 *PointE1, p2 *PointE1) {
	C.E1_add((*C.E1)(res), (*C.E1)(p1), (*C.E1)(p2))
}

// Addition in E2, used in benchmark
func addE2(res *PointE2, p1 *PointE2, p2 *PointE2) {
	C.E2_add((*C.E2)(res), (*C.E2)(p1), (*C.E2)(p2))
}

// modular multiplication in F_r, used in benchmark only
// it currently calls a Montgomery multiplication
func multFr(res *Scalar, f1 *Scalar, f2 *Scalar) {
	C.Fr_mul_montg((*C.Fr)(res), (*C.Fr)(f1), (*C.Fr)(f2))
}
