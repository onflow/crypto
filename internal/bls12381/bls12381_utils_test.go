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

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/onflow/crypto/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sanity check of G1 and G2 scalar multiplication
func TestScalarMultBLS12381(t *testing.T) {
	expoBytes, err := hex.DecodeString("444465cb6cc2dba9474e6beeb6a9013fbf1260d073429fb14a31e63e89129390")
	require.NoError(t, err)

	var expo Scalar
	isZero := MapToFr(&expo, expoBytes)
	require.False(t, isZero)

	// G1 generator multiplication
	// Note that generator and random point multiplications
	// are implemented with the same algorithm
	t.Run("G1", func(t *testing.T) {
		if !IsG1Compressed() {
			t.Skip()
		}
		var p PointE1
		GeneratorScalarMultG1(&p, &expo)
		expected, err := hex.DecodeString("96484ca50719f5d2533047960878b6bae8289646c0f00a942a1e6992be9981a9e0c7a51e9918f9b19d178cf04a8018a4")
		require.NoError(t, err)
		pBytes := make([]byte, G1BytesLen)
		WritePointE1(pBytes, &p)
		assert.Equal(t, pBytes, expected)
	})

	// G2 generator multiplication
	// Note that generator and random point multiplications
	// are implemented with the same algorithm
	t.Run("G2", func(t *testing.T) {
		if !IsG2Compressed() {
			t.Skip()
		}
		var p PointE2
		GeneratorScalarMultG2(&p, &expo)
		expected, err := hex.DecodeString("b35f5043f166848805b98da62dcb9c5d2f25e497bd0d9c461d4a00d19e4e67cc1e813de3c99479d5a2c62fb754fd7df40c4fd60c46834c8ae665343a3ff7dc3cc929de34ad62b7b55974f4e3fd20990d3e564b96e4d33de87716052d58cf823e")
		require.NoError(t, err)
		pBytes := make([]byte, G2BytesLen)
		WritePointE2(pBytes, &p)
		assert.Equal(t, pBytes, expected)
	})
}

// G1 and G2 operations
func BenchmarkGroupOperations(b *testing.B) {
	seed := make([]byte, 2*FrBytesLen)
	_, err := rand.Read(seed)
	require.NoError(b, err)

	var expo Scalar
	isZero := MapToFr(&expo, seed)
	require.False(b, isZero)

	var res PointE1
	// G1 generator multiplication
	// Note that generator and random point multiplications
	// are currently implemented with the same algorithm
	b.Run("G1 gen expo", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			GeneratorScalarMultG1(&res, &expo)
		}
	})

	// E1 random point multiplication
	// Note that generator and random point multiplications
	// are currently implemented with the same algorithm
	b.Run("E1 rand expo", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			res.ScalarMultE1(&res, &expo)
		}
	})

	// G2 generator multiplication
	// Note that generator and random point multiplications
	// are implemented with the same algorithm
	b.Run("G2 gen expo", func(b *testing.B) {
		var res PointE2
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			GeneratorScalarMultG2(&res, &expo)
		}
	})

	var p1, p2 PointE1
	unsafeMapToG1(&p1, seed[:FrBytesLen])
	unsafeMapToG1(&p2, seed[FrBytesLen:])

	b.Run("G1 add", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			addE1(&p1, &p1, &p2)
		}
	})

	var q1, q2 PointE2
	unsafeMapToG2(&q1, seed[:FrBytesLen])
	unsafeMapToG2(&q2, seed[FrBytesLen:])

	b.Run("G2 add", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			addE2(&q1, &q1, &q2)
		}
	})
}

// Sanity-check of the map-to-G1 with regards to the IETF draft hash-to-curve
func TestMapToG1(t *testing.T) {
	if !IsG1Compressed() {
		t.Skip()
	}
	// test vectors from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#appendix-J.9.1
	dst := []byte("QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_")

	msgs := [][]byte{
		[]byte{},
		[]byte("abc"),
		[]byte("abcdef0123456789"),
		[]byte("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"),
		[]byte("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	}

	expectedPointString := []string{
		"052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
		"03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
		"11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
		"15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
		"082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
	}

	for i, msg := range msgs {
		pointBytes := hashToG1Bytes(msg, dst)
		require.NotNil(t, pointBytes)

		expectedPointBytes, err := hex.DecodeString(expectedPointString[i])
		require.NoError(t, err)
		// skip comparing the first 3 bits that depend on the serialization scheme
		pointBytes[0] = (expectedPointBytes[0] & 0xE0) | (pointBytes[0] & 0x1F)
		assert.Equal(t, expectedPointBytes, pointBytes, "map to G1 should match the IETF draft test vector")
	}
}

// Hashing to G1 bench
func BenchmarkMapToG1(b *testing.B) {
	input := make([]byte, ExpandMsgOutput)
	for i := 0; i < len(input); i++ {
		input[i] = byte(i)
	}
	b.ResetTimer()
	var p *PointE1
	for i := 0; i < b.N; i++ {
		p = MapToG1(input)
	}
	require.NotNil(b, p)
}

// test subgroup membership check in G1 and G2
func TestSubgroupCheck(t *testing.T) {
	prg := internal.GetPRG(t)
	seed := make([]byte, 192)
	_, err := prg.Read(seed)
	require.NoError(t, err)

	t.Run("G1", func(t *testing.T) {
		var p PointE1
		unsafeMapToG1(&p, seed) // point in G1
		assert.True(t, p.CheckMembershipG1())

		UnsafeMapToG1Complement(&p, seed) // point in E2\G2
		assert.False(t, p.CheckMembershipG1())
	})

	t.Run("G2", func(t *testing.T) {
		var p PointE2
		unsafeMapToG2(&p, seed) // point in G2
		assert.True(t, p.CheckMembershipG2())

		unsafeMapToG2Complement(&p, seed) // point in E2\G2
		assert.False(t, p.CheckMembershipG2())
	})
}

// subgroup membership check bench
func BenchmarkSubgroupCheck(b *testing.B) {
	seed := make([]byte, G2BytesLen)
	_, err := rand.Read(seed)
	require.NoError(b, err)

	b.Run("G1", func(b *testing.B) {
		var p PointE1
		unsafeMapToG1(&p, seed) // point in G1
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = p.CheckMembershipG1() // G1
		}
	})

	b.Run("G2", func(b *testing.B) {
		var p PointE2
		unsafeMapToG2(&p, seed) // point in G2
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = p.CheckMembershipG2() // G2
		}
	})
}

// specific test of G1 points Encode and decode (BLS signature since the library is set for min_sig).
// G2 points read and write are implicitly tested by public keys Encode/Decode.
func TestReadWriteG1(t *testing.T) {
	prg := internal.GetPRG(t)
	seed := make([]byte, FrBytesLen)
	bytes := make([]byte, G1BytesLen)
	// generate a random G1 point, encode it, decode it,
	// and compare it the original point
	t.Run("random points", func(t *testing.T) {
		iterations := 50
		for i := 0; i < iterations; i++ {
			var p, q PointE1
			_, err := prg.Read(seed)
			unsafeMapToG1(&p, seed)
			require.NoError(t, err)
			WritePointE1(bytes, &p)
			err = ReadPointE1(&q, bytes)
			require.NoError(t, err)
			assert.True(t, p.Equals(&q))
		}
	})

	t.Run("infinity", func(t *testing.T) {
		var p, q PointE1
		seed := make([]byte, FrBytesLen)
		unsafeMapToG1(&p, seed) // this results in the infinity point given how `unsafeMapToG1` works with an empty scalar
		WritePointE1(bytes, &p)
		unsafeMapToG1(&p, seed) // this results in the infinity point given how `unsafeMapToG1` works with an empty scalar
		WritePointE1(bytes, &p)
		require.Equal(t, bytes, G1Serialization) // sanity check
		err := ReadPointE1(&q, bytes)
		require.NoError(t, err)
		assert.True(t, p.Equals(&q))
	})
}

// test some edge cases of MapToFr to validate modular reduction and endianness:
//   - inputs `0` and curve order `r`
//   - inputs `1` and `r+1`
func TestMapToFr(t *testing.T) {
	var x Scalar
	offset := 10
	bytes := make([]byte, FrBytesLen+offset)
	expectedEncoding := make([]byte, FrBytesLen)
	// zero bytes
	isZero := MapToFr(&x, bytes)
	assert.True(t, isZero)
	assert.True(t, x.IsZero())
	assert.Equal(t, expectedEncoding, x.Encode())
	// curve order bytes
	copy(bytes[offset:], BLS12381Order)
	isZero = MapToFr(&x, bytes)
	assert.True(t, isZero)
	assert.True(t, x.IsZero())
	assert.Equal(t, expectedEncoding, x.Encode())
	// curve order + 1
	g1, err := hex.DecodeString("824aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")
	require.NoError(t, err)
	bytes[len(bytes)-1] += 1
	isZero = MapToFr(&x, bytes)
	assert.False(t, isZero)
	assert.False(t, x.IsZero())
	expectedEncoding[FrBytesLen-1] = 1
	assert.Equal(t, expectedEncoding, x.Encode())
	// check scalar is equal to "1" in the lower layer (scalar multiplication)
	var y PointE2
	GeneratorScalarMultG2(&y, &x)
	assert.Equal(t, y.Encode(), g1, "scalar should be 1, check endianness in the C layer")
	// 1
	copy(bytes[offset:], expectedEncoding)
	isZero = MapToFr(&x, bytes)
	assert.False(t, isZero)
	assert.False(t, x.IsZero())
	expectedEncoding[FrBytesLen-1] = 1
	assert.Equal(t, expectedEncoding, x.Encode())
	// check scalar is equal to "1" in the lower layer (scalar multiplication)
	GeneratorScalarMultG2(&y, &x)
	assert.Equal(t, y.Encode(), g1, "scalar should be 1, check endianness in the C layer")
}

// pairing bench
func BenchmarkPairing(b *testing.B) {
	const pairingsNumber = 3

	// Build random G1 ad G2 points
	seed := make([]byte, pairingsNumber*FrBytesLen)
	_, err := rand.Read(seed)
	require.NoError(b, err)

	pointsG1 := make([]PointE1, pairingsNumber)
	pointsG2 := make([]PointE2, pairingsNumber)
	for i := 0; i < pairingsNumber; i++ {
		unsafeMapToG1(&pointsG1[i], seed[i*FrBytesLen:(i+1)*FrBytesLen])
		unsafeMapToG2(&pointsG2[i], seed[i*FrBytesLen:(i+1)*FrBytesLen])
	}

	for p := 1; p <= pairingsNumber; p++ {
		b.Run(fmt.Sprintf("%d pairing(s)", p), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				multiPairing(pointsG1[:p], pointsG2[:p])
			}
		})
	}
}

// F_r operations
func BenchmarkFrOperation(b *testing.B) {
	seed := make([]byte, 2*FrBytesLen)
	_, err := rand.Read(seed)
	require.NoError(b, err)

	var f1, f2 Scalar
	isZero := MapToFr(&f1, seed[:FrBytesLen])
	require.False(b, isZero)
	isZero = MapToFr(&f2, seed[FrBytesLen:])
	require.False(b, isZero)

	b.Run("modular mult", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			multFr(&f1, &f1, &f2) // G1
		}
	})
}
