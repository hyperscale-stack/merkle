// Copyright 2026 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package merkle

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProofSerializeDeserialize(t *testing.T) {
	tests := []struct {
		name     string
		hashType HashType
	}{
		{"SHA256", HashTypeSHA256},
		{"SHA384", HashTypeSHA384},
		{"SHA512", HashTypeSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashSize := tt.hashType.Size()
			siblings := []Sibling{
				{Direction: Left, Hash: bytes.Repeat([]byte{0xAA}, hashSize)},
				{Direction: Right, Hash: bytes.Repeat([]byte{0xBB}, hashSize)},
				{Direction: Left, Hash: bytes.Repeat([]byte{0xCC}, hashSize)},
			}

			original := &Proof{
				LeafIndex: 5,
				Siblings:  siblings,
				HashType:  tt.hashType,
			}

			serialized := original.Serialize()
			require.NotNil(t, serialized)

			deserialized, err := DeserializeProof(serialized)
			require.NoError(t, err)
			require.NotNil(t, deserialized)

			assert.Equal(t, original.HashType, deserialized.HashType)
			assert.Equal(t, len(original.Siblings), len(deserialized.Siblings))

			for i := range original.Siblings {
				assert.Equal(t, original.Siblings[i].Direction, deserialized.Siblings[i].Direction)
				assert.Equal(t, original.Siblings[i].Hash, deserialized.Siblings[i].Hash)
			}
		})
	}
}

func TestProofSerializeFormat(t *testing.T) {
	hashSize := HashTypeSHA256.Size()
	siblings := []Sibling{
		{Direction: Left, Hash: bytes.Repeat([]byte{0x11}, hashSize)},
		{Direction: Right, Hash: bytes.Repeat([]byte{0x22}, hashSize)},
	}

	proof := &Proof{
		LeafIndex: 0,
		Siblings:  siblings,
		HashType:  HashTypeSHA256,
	}

	serialized := proof.Serialize()

	// Check format
	assert.Equal(t, byte(0x01), serialized[0], "Version should be 0x01")
	assert.Equal(t, byte(HashTypeSHA256), serialized[1], "HashType should be SHA256")
	assert.Equal(t, byte(2), serialized[2], "Number of siblings should be 2")

	// Check first sibling
	assert.Equal(t, byte(Left), serialized[3], "First sibling direction should be Left")
	assert.Equal(t, bytes.Repeat([]byte{0x11}, hashSize), serialized[4:4+hashSize])

	// Check second sibling
	offset := 4 + hashSize
	assert.Equal(t, byte(Right), serialized[offset], "Second sibling direction should be Right")
	assert.Equal(t, bytes.Repeat([]byte{0x22}, hashSize), serialized[offset+1:offset+1+hashSize])

	// Check total size
	expectedSize := 3 + 2*(1+hashSize)
	assert.Equal(t, expectedSize, len(serialized))
}

func TestDeserializeProofErrors(t *testing.T) {
	t.Run("Too short", func(t *testing.T) {
		_, err := DeserializeProof([]byte{0x01, 0x00})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too short")
	})

	t.Run("Invalid version", func(t *testing.T) {
		_, err := DeserializeProof([]byte{0x99, 0x00, 0x00})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported proof version")
	})

	t.Run("Invalid hash type", func(t *testing.T) {
		_, err := DeserializeProof([]byte{0x01, 0x99, 0x00})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid hash type")
	})

	t.Run("Size mismatch", func(t *testing.T) {
		// Claim 1 sibling but don't provide enough data
		_, err := DeserializeProof([]byte{0x01, 0x00, 0x01, 0x00})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "size mismatch")
	})

	t.Run("Empty proof is valid", func(t *testing.T) {
		proof, err := DeserializeProof([]byte{0x01, 0x00, 0x00})
		require.NoError(t, err)
		assert.Equal(t, 0, len(proof.Siblings))
	})
}

func TestProofVerifyEndToEnd(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		hashType HashType
		leaves   [][]byte
	}{
		{
			name:     "SHA256 with 4 leaves",
			hashType: HashTypeSHA256,
			leaves: [][]byte{
				SHA256([]byte("leaf0")),
				SHA256([]byte("leaf1")),
				SHA256([]byte("leaf2")),
				SHA256([]byte("leaf3")),
			},
		},
		{
			name:     "SHA384 with 5 leaves",
			hashType: HashTypeSHA384,
			leaves: [][]byte{
				SHA384([]byte("item0")),
				SHA384([]byte("item1")),
				SHA384([]byte("item2")),
				SHA384([]byte("item3")),
				SHA384([]byte("item4")),
			},
		},
		{
			name:     "SHA512 with 3 leaves",
			hashType: HashTypeSHA512,
			leaves: [][]byte{
				SHA512([]byte("data0")),
				SHA512([]byte("data1")),
				SHA512([]byte("data2")),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := New(ctx, tt.leaves, WithHashType(tt.hashType))
			require.NotNil(t, tree)

			root := tree.RootHash()
			require.NotNil(t, root)

			// Verify proof for each leaf
			for i, leaf := range tt.leaves {
				proof := tree.GenerateProof(uint32(i))
				require.NotNil(t, proof, "Proof for leaf %d should not be nil", i)

				valid := proof.Verify(leaf, root)
				assert.True(t, valid, "Proof for leaf %d should be valid", i)

				// Test round-trip serialization
				serialized := proof.Serialize()
				deserialized, err := DeserializeProof(serialized)
				require.NoError(t, err)

				valid = deserialized.Verify(leaf, root)
				assert.True(t, valid, "Deserialized proof for leaf %d should be valid", i)
			}
		})
	}
}

func TestProofVerifyInvalidLeaf(t *testing.T) {
	ctx := context.Background()

	leaves := [][]byte{
		SHA256([]byte("leaf0")),
		SHA256([]byte("leaf1")),
		SHA256([]byte("leaf2")),
		SHA256([]byte("leaf3")),
	}

	tree := New(ctx, leaves, WithHashType(HashTypeSHA256))
	root := tree.RootHash()

	proof := tree.GenerateProof(0)

	// Verify with wrong leaf
	wrongLeaf := SHA256([]byte("wrong"))
	valid := proof.Verify(wrongLeaf, root)
	assert.False(t, valid, "Proof should not verify with wrong leaf")
}

func TestProofVerifyInvalidRoot(t *testing.T) {
	ctx := context.Background()

	leaves := [][]byte{
		SHA256([]byte("leaf0")),
		SHA256([]byte("leaf1")),
		SHA256([]byte("leaf2")),
		SHA256([]byte("leaf3")),
	}

	tree := New(ctx, leaves, WithHashType(HashTypeSHA256))

	proof := tree.GenerateProof(0)

	// Verify with wrong root
	wrongRoot := SHA256([]byte("wrong root"))
	valid := proof.Verify(leaves[0], wrongRoot)
	assert.False(t, valid, "Proof should not verify with wrong root")
}

func TestProofVerifyTampered(t *testing.T) {
	ctx := context.Background()

	leaves := [][]byte{
		SHA256([]byte("leaf0")),
		SHA256([]byte("leaf1")),
		SHA256([]byte("leaf2")),
		SHA256([]byte("leaf3")),
	}

	tree := New(ctx, leaves, WithHashType(HashTypeSHA256))
	root := tree.RootHash()

	proof := tree.GenerateProof(0)

	// Tamper with a sibling hash
	if len(proof.Siblings) > 0 {
		proof.Siblings[0].Hash[0] ^= 0xFF
	}

	valid := proof.Verify(leaves[0], root)
	assert.False(t, valid, "Tampered proof should not verify")
}

func TestProofVerifyNilProof(t *testing.T) {
	var proof *Proof
	valid := proof.Verify([]byte("leaf"), []byte("root"))
	assert.False(t, valid, "Nil proof should not verify")
}

func TestProofSerializeNilProof(t *testing.T) {
	var proof *Proof
	result := proof.Serialize()
	assert.Nil(t, result, "Nil proof should serialize to nil")
}

func TestProofWithSingleLeaf(t *testing.T) {
	ctx := context.Background()

	leaf := SHA256([]byte("only leaf"))
	leaves := [][]byte{leaf}

	tree := New(ctx, leaves, WithHashType(HashTypeSHA256))
	require.NotNil(t, tree)

	root := tree.RootHash()
	require.NotNil(t, root)

	proof := tree.GenerateProof(0)
	require.NotNil(t, proof)

	// Single leaf tree should have one sibling (the duplicated leaf)
	valid := proof.Verify(leaf, root)
	assert.True(t, valid, "Proof for single leaf should be valid")
}

func TestProofWithTwoLeaves(t *testing.T) {
	ctx := context.Background()

	leaves := [][]byte{
		SHA256([]byte("leaf0")),
		SHA256([]byte("leaf1")),
	}

	tree := New(ctx, leaves, WithHashType(HashTypeSHA256))
	require.NotNil(t, tree)

	root := tree.RootHash()

	// Check proof for first leaf
	proof0 := tree.GenerateProof(0)
	require.NotNil(t, proof0)
	assert.Equal(t, 1, len(proof0.Siblings))
	assert.Equal(t, Right, proof0.Siblings[0].Direction)
	assert.True(t, proof0.Verify(leaves[0], root))

	// Check proof for second leaf
	proof1 := tree.GenerateProof(1)
	require.NotNil(t, proof1)
	assert.Equal(t, 1, len(proof1.Siblings))
	assert.Equal(t, Left, proof1.Siblings[0].Direction)
	assert.True(t, proof1.Verify(leaves[1], root))
}

func TestGenerateProofOutOfBounds(t *testing.T) {
	ctx := context.Background()

	leaves := [][]byte{
		SHA256([]byte("leaf0")),
		SHA256([]byte("leaf1")),
	}

	tree := New(ctx, leaves, WithHashType(HashTypeSHA256))

	proof := tree.GenerateProof(10)
	assert.Nil(t, proof, "Out of bounds index should return nil proof")
}

func TestTreeLeafCount(t *testing.T) {
	ctx := context.Background()

	t.Run("Normal tree", func(t *testing.T) {
		leaves := [][]byte{
			SHA256([]byte("leaf0")),
			SHA256([]byte("leaf1")),
			SHA256([]byte("leaf2")),
		}
		tree := New(ctx, leaves, WithHashType(HashTypeSHA256))
		assert.Equal(t, 3, tree.LeafCount())
	})

	t.Run("Nil tree", func(t *testing.T) {
		var tree *Tree
		assert.Equal(t, 0, tree.LeafCount())
	})
}

func BenchmarkProofSerialize(b *testing.B) {
	hashSize := HashTypeSHA384.Size()
	siblings := make([]Sibling, 20)
	for i := range siblings {
		siblings[i] = Sibling{
			Direction: Direction(i % 2),
			Hash:      bytes.Repeat([]byte{byte(i)}, hashSize),
		}
	}

	proof := &Proof{
		LeafIndex: 12345,
		Siblings:  siblings,
		HashType:  HashTypeSHA384,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = proof.Serialize()
	}
}

func BenchmarkProofDeserialize(b *testing.B) {
	hashSize := HashTypeSHA384.Size()
	siblings := make([]Sibling, 20)
	for i := range siblings {
		siblings[i] = Sibling{
			Direction: Direction(i % 2),
			Hash:      bytes.Repeat([]byte{byte(i)}, hashSize),
		}
	}

	proof := &Proof{
		LeafIndex: 12345,
		Siblings:  siblings,
		HashType:  HashTypeSHA384,
	}
	data := proof.Serialize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeProof(data)
	}
}

func BenchmarkProofVerify(b *testing.B) {
	ctx := context.Background()

	leaves := make([][]byte, 1000)
	for i := range leaves {
		leaves[i] = SHA384([]byte{byte(i), byte(i >> 8)})
	}

	tree := New(ctx, leaves, WithHashType(HashTypeSHA384))
	root := tree.RootHash()
	proof := tree.GenerateProof(500)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = proof.Verify(leaves[500], root)
	}
}
