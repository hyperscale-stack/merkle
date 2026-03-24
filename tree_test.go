// Copyright 2026 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package merkle

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuild(t *testing.T) {
	t.Run("Test empry tree", func(t *testing.T) {
		ctx := context.Background()

		leaves := [][]byte{}
		tree := Build(ctx, leaves)
		assert.Nil(t, tree)
	})

	t.Run("Test tree sha256 with inpair leaves and default config", func(t *testing.T) {
		ctx := context.Background()

		leaves := [][]byte{
			[]byte("leaf1"),
			[]byte("leaf2"),
			[]byte("leaf3"),
		}

		tree := Build(ctx, leaves)

		leaves = append(leaves, leaves[2]) // Duplicate the last leaf

		assert.NotNil(t, tree)
		assert.Equal(t, 4, len(tree.Leaves))
		assert.Equal(t, leaves, tree.Leaves)
		assert.Equal(t, []byte{0x38, 0xc4, 0x47, 0x40, 0x41, 0xbc, 0x71, 0x73, 0x7a, 0x91, 0x55, 0xbc, 0x9d, 0x7e, 0x8f, 0x61, 0xfe, 0x49, 0xca, 0x81, 0x66, 0x76, 0xf6, 0x68, 0x6b, 0x29, 0x4e, 0x1b, 0x51, 0xe5, 0xa4, 0xe}, tree.Root.Value)
	})

	t.Run("Test tree sha256 with inpair leaves and duplicate strategy config", func(t *testing.T) {
		ctx := context.Background()

		leaves := [][]byte{
			[]byte("leaf1"),
			[]byte("leaf2"),
			[]byte("leaf3"),
		}

		tree := Build(ctx, leaves, WithBalanceStrategy(DuplicateLastLeaf))

		leaves = append(leaves, leaves[2]) // Duplicate the last leaf

		assert.NotNil(t, tree)
		assert.Equal(t, 4, len(tree.Leaves))
		assert.Equal(t, leaves, tree.Leaves)
		assert.Equal(t, []byte{0x38, 0xc4, 0x47, 0x40, 0x41, 0xbc, 0x71, 0x73, 0x7a, 0x91, 0x55, 0xbc, 0x9d, 0x7e, 0x8f, 0x61, 0xfe, 0x49, 0xca, 0x81, 0x66, 0x76, 0xf6, 0x68, 0x6b, 0x29, 0x4e, 0x1b, 0x51, 0xe5, 0xa4, 0xe}, tree.Root.Value)
	})

	t.Run("Test tree sha256 with inpair leaves and padded strategy config", func(t *testing.T) {
		ctx := context.Background()

		leaves := [][]byte{
			[]byte("leaf1"),
			[]byte("leaf2"),
			[]byte("leaf3"),
		}

		tree := Build(ctx, leaves, WithPaddingValue([]byte("padding")))

		leaves = append(leaves, []byte("padding")) // Duplicate the last leaf

		assert.NotNil(t, tree)
		assert.Equal(t, 4, len(tree.Leaves))
		assert.Equal(t, leaves, tree.Leaves)
		assert.Equal(t, []byte{0xc5, 0x27, 0x69, 0x14, 0x34, 0x31, 0x95, 0xb9, 0xfc, 0x54, 0x0, 0x82, 0x3d, 0xdd, 0xa4, 0x8e, 0x3b, 0xf5, 0xb8, 0xa5, 0x34, 0x6c, 0xf1, 0x21, 0x52, 0xd5, 0xdf, 0x83, 0xe, 0x40, 0x30, 0x6b}, tree.Root.Value)
	})

	t.Run("Test tree sha256 with pair leaves and default config", func(t *testing.T) {
		ctx := context.Background()

		leaves := [][]byte{
			[]byte("leaf1"),
			[]byte("leaf2"),
			[]byte("leaf3"),
			[]byte("leaf4"),
		}

		tree := Build(ctx, leaves)

		assert.NotNil(t, tree)
		assert.Equal(t, 4, len(tree.Leaves))
		assert.Equal(t, leaves, tree.Leaves)
		assert.Equal(t, []uint8([]byte{0xfa, 0xd5, 0x1, 0xd8, 0xe0, 0xd4, 0xa1, 0x25, 0xfd, 0x74, 0x9a, 0x9d, 0xc4, 0xbe, 0x90, 0xa1, 0x1e, 0x6b, 0xce, 0x3a, 0x53, 0x19, 0xb2, 0xca, 0xfd, 0x81, 0x50, 0x2d, 0xa9, 0xf4, 0x17, 0x4d}), tree.Root.Value)
	})

	t.Run("Test tree sha384 with inpair leaves and default config", func(t *testing.T) {
		ctx := context.Background()

		leaves := [][]byte{
			[]byte("leaf1"),
			[]byte("leaf2"),
			[]byte("leaf3"),
		}

		tree := Build(ctx, leaves, WithHashFunc(SHA384))

		leaves = append(leaves, leaves[2]) // Duplicate the last leaf

		assert.NotNil(t, tree)
		assert.Equal(t, 4, len(tree.Leaves))
		assert.Equal(t, leaves, tree.Leaves)
		assert.Equal(t, []byte{0x51, 0x69, 0xc2, 0xb0, 0x28, 0x1, 0xd5, 0x29, 0xf7, 0x6c, 0x88, 0x5b, 0xe0, 0x29, 0x51, 0x92, 0xdb, 0x82, 0xfe, 0x40, 0x45, 0x9f, 0xbc, 0x99, 0xb6, 0x7b, 0xe4, 0xd9, 0x19, 0x53, 0x96, 0xf, 0x4e, 0x2f, 0xaa, 0xb8, 0x3b, 0x52, 0xec, 0x65, 0x9a, 0x94, 0x32, 0x32, 0x61, 0xcf, 0x24, 0x9e}, tree.Root.Value)
	})

	t.Run("Test tree sha256 with inpair leaves and default config trusted", func(t *testing.T) {
		ctx := context.Background()

		expectedRoot := SHA256(
			append(
				SHA256(append([]byte("leaf1"), []byte("leaf2")...)),
				SHA256(append([]byte("leaf3"), []byte("leaf3")...))...,
			),
		)

		leaves := [][]byte{
			[]byte("leaf1"),
			[]byte("leaf2"),
			[]byte("leaf3"),
		}

		tree := Build(ctx, leaves)

		leaves = append(leaves, leaves[2]) // Duplicate the last leaf

		assert.NotNil(t, tree)
		assert.Equal(t, 4, len(tree.Leaves))
		assert.Equal(t, leaves, tree.Leaves)
		assert.Equal(t, expectedRoot, tree.Root.Value)
	})

	t.Run("Test tree sha384 with inpair leaves and default config trusted", func(t *testing.T) {
		ctx := context.Background()

		expectedRoot := SHA384(
			append(
				SHA384(append([]byte("leaf1"), []byte("leaf2")...)),
				SHA384(append([]byte("leaf3"), []byte("leaf3")...))...,
			),
		)

		leaves := [][]byte{
			[]byte("leaf1"),
			[]byte("leaf2"),
			[]byte("leaf3"),
		}

		tree := Build(ctx, leaves, WithHashFunc(SHA384))

		leaves = append(leaves, leaves[2]) // Duplicate the last leaf

		assert.NotNil(t, tree)
		assert.Equal(t, 4, len(tree.Leaves))
		assert.Equal(t, leaves, tree.Leaves)
		assert.Equal(t, expectedRoot, tree.Root.Value)
	})

	t.Run("Test tree sha256 with inpair leaves and duplicate strategy config trusted", func(t *testing.T) {
		ctx := context.Background()

		expectedRoot := SHA256(
			append(
				SHA256(append(SHA256([]byte("leaf1")), SHA256([]byte("leaf2"))...)),
				SHA256(append(SHA256([]byte("leaf3")), SHA256([]byte("leaf3"))...))...,
			),
		)

		leaves := [][]byte{
			SHA256([]byte("leaf1")),
			SHA256([]byte("leaf2")),
			SHA256([]byte("leaf3")),
		}

		tree := Build(ctx, leaves, WithBalanceStrategy(DuplicateLastLeaf))

		leaves = append(leaves, leaves[2]) // Duplicate the last leaf

		assert.NotNil(t, tree)
		assert.Equal(t, 4, len(tree.Leaves))
		assert.Equal(t, leaves, tree.Leaves)
		assert.Equal(t, expectedRoot, tree.Root.Value)
	})

	t.Run("Test tree sha384 with inpair leaves and duplicate strategy config trusted", func(t *testing.T) {
		ctx := context.Background()

		expectedRoot := SHA384(
			append(
				SHA384(append(SHA384([]byte("leaf1")), SHA384([]byte("leaf2"))...)),
				SHA384(append(SHA384([]byte("leaf3")), SHA384([]byte("leaf3"))...))...,
			),
		)

		leaves := [][]byte{
			SHA384([]byte("leaf1")),
			SHA384([]byte("leaf2")),
			SHA384([]byte("leaf3")),
		}

		tree := Build(ctx, leaves, WithBalanceStrategy(DuplicateLastLeaf), WithHashFunc(SHA384))

		leaves = append(leaves, leaves[2]) // Duplicate the last leaf

		assert.NotNil(t, tree)
		assert.Equal(t, 4, len(tree.Leaves))
		assert.Equal(t, leaves, tree.Leaves)
		assert.Equal(t, expectedRoot, tree.Root.Value)
	})
}

func BenchmarkBuild(b *testing.B) {
	ctx := context.Background()

	leaves := [][]byte{
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
		[]byte("leaf4"),
	}

	for i := 0; i < b.N; i++ {
		_ = Build(ctx, leaves)
	}
}

func BenchmarkNewTreeSHA256Complete(b *testing.B) {
	ctx := context.Background()

	for i := 0; i < b.N; i++ {
		leaves := [][]byte{
			SHA256([]byte("euskadi31@gmail.com")),       // from
			SHA256([]byte("a.etcheverry@mailstone.fr")), // to
			SHA256([]byte("e.sabber@mailstone.fr")),     // to
			SHA256([]byte("steve@apple.com")),           // cc
			SHA256([]byte("steve.woz@apple.com")),       // cc
		}

		_ = Build(ctx, leaves)
	}
}

func TestNew(t *testing.T) {
	t.Run("Empty tree", func(t *testing.T) {
		ctx := context.Background()
		tree := New(ctx, [][]byte{})
		assert.Nil(t, tree)
	})

	t.Run("Single leaf", func(t *testing.T) {
		ctx := context.Background()
		leaf := SHA256([]byte("single"))
		tree := New(ctx, [][]byte{leaf}, WithHashType(HashTypeSHA256))

		assert.NotNil(t, tree)
		assert.NotNil(t, tree.RootHash())
		assert.Equal(t, 1, tree.LeafCount())

		proof := tree.GenerateProof(0)
		assert.NotNil(t, proof)
		assert.True(t, proof.Verify(leaf, tree.RootHash()))
	})

	t.Run("Two leaves", func(t *testing.T) {
		ctx := context.Background()
		leaves := [][]byte{
			SHA256([]byte("leaf0")),
			SHA256([]byte("leaf1")),
		}
		tree := New(ctx, leaves, WithHashType(HashTypeSHA256))

		assert.NotNil(t, tree)
		assert.Equal(t, 2, tree.LeafCount())

		// Both proofs should verify
		for i, leaf := range leaves {
			proof := tree.GenerateProof(uint32(i))
			assert.NotNil(t, proof)
			assert.True(t, proof.Verify(leaf, tree.RootHash()), "Proof for leaf %d should verify", i)
		}
	})

	t.Run("Power of two leaves (4)", func(t *testing.T) {
		ctx := context.Background()
		leaves := [][]byte{
			SHA256([]byte("a")),
			SHA256([]byte("b")),
			SHA256([]byte("c")),
			SHA256([]byte("d")),
		}
		tree := New(ctx, leaves, WithHashType(HashTypeSHA256))

		assert.NotNil(t, tree)
		assert.Equal(t, 4, tree.LeafCount())

		// All proofs should verify
		for i, leaf := range leaves {
			proof := tree.GenerateProof(uint32(i))
			assert.NotNil(t, proof)
			assert.Equal(t, 2, len(proof.Siblings), "4-leaf tree should have 2 siblings in proof")
			assert.True(t, proof.Verify(leaf, tree.RootHash()), "Proof for leaf %d should verify", i)
		}
	})

	t.Run("Odd leaves (5)", func(t *testing.T) {
		ctx := context.Background()
		leaves := [][]byte{
			SHA384([]byte("0")),
			SHA384([]byte("1")),
			SHA384([]byte("2")),
			SHA384([]byte("3")),
			SHA384([]byte("4")),
		}
		tree := New(ctx, leaves, WithHashType(HashTypeSHA384))

		assert.NotNil(t, tree)
		assert.Equal(t, 5, tree.LeafCount())
		assert.Equal(t, 48, len(tree.RootHash())) // SHA384 = 48 bytes

		// All proofs should verify
		for i, leaf := range leaves {
			proof := tree.GenerateProof(uint32(i))
			assert.NotNil(t, proof)
			assert.True(t, proof.Verify(leaf, tree.RootHash()), "Proof for leaf %d should verify", i)
		}
	})

	t.Run("SHA512 hash type", func(t *testing.T) {
		ctx := context.Background()
		leaves := [][]byte{
			SHA512([]byte("x")),
			SHA512([]byte("y")),
			SHA512([]byte("z")),
		}
		tree := New(ctx, leaves, WithHashType(HashTypeSHA512))

		assert.NotNil(t, tree)
		assert.Equal(t, 64, len(tree.RootHash())) // SHA512 = 64 bytes

		for i, leaf := range leaves {
			proof := tree.GenerateProof(uint32(i))
			assert.NotNil(t, proof)
			assert.Equal(t, HashTypeSHA512, proof.HashType)
			assert.True(t, proof.Verify(leaf, tree.RootHash()))
		}
	})

	t.Run("Large tree (1000 leaves)", func(t *testing.T) {
		ctx := context.Background()
		leaves := make([][]byte, 1000)
		for i := range leaves {
			leaves[i] = SHA256([]byte{byte(i), byte(i >> 8)})
		}

		tree := New(ctx, leaves, WithHashType(HashTypeSHA256))

		assert.NotNil(t, tree)
		assert.Equal(t, 1000, tree.LeafCount())

		// Spot check some proofs
		for _, idx := range []int{0, 1, 499, 500, 999} {
			proof := tree.GenerateProof(uint32(idx))
			assert.NotNil(t, proof)
			assert.True(t, proof.Verify(leaves[idx], tree.RootHash()), "Proof for leaf %d should verify", idx)
		}
	})
}

func TestTreeRootHash(t *testing.T) {
	t.Run("Nil tree", func(t *testing.T) {
		var tree *Tree
		assert.Nil(t, tree.RootHash())
	})

	t.Run("Tree with nil root", func(t *testing.T) {
		tree := &Tree{Root: nil}
		assert.Nil(t, tree.RootHash())
	})
}

func TestGenerateProofEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("Nil tree", func(t *testing.T) {
		var tree *Tree
		proof := tree.GenerateProof(0)
		assert.Nil(t, proof)
	})

	t.Run("Index out of bounds", func(t *testing.T) {
		leaves := [][]byte{SHA256([]byte("a")), SHA256([]byte("b"))}
		tree := New(ctx, leaves, WithHashType(HashTypeSHA256))

		assert.Nil(t, tree.GenerateProof(2))
		assert.Nil(t, tree.GenerateProof(100))
	})
}

func TestNewDeterministic(t *testing.T) {
	ctx := context.Background()

	leaves := [][]byte{
		SHA256([]byte("deterministic")),
		SHA256([]byte("test")),
		SHA256([]byte("data")),
	}

	// Build tree multiple times
	tree1 := New(ctx, leaves, WithHashType(HashTypeSHA256))
	tree2 := New(ctx, leaves, WithHashType(HashTypeSHA256))

	// Roots should be identical
	assert.Equal(t, tree1.RootHash(), tree2.RootHash())

	// Proofs should be identical
	for i := range leaves {
		proof1 := tree1.GenerateProof(uint32(i))
		proof2 := tree2.GenerateProof(uint32(i))

		assert.Equal(t, proof1.Serialize(), proof2.Serialize())
	}
}

func BenchmarkNew(b *testing.B) {
	ctx := context.Background()
	leaves := make([][]byte, 100)
	for i := range leaves {
		leaves[i] = SHA256([]byte{byte(i)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = New(ctx, leaves, WithHashType(HashTypeSHA256))
	}
}

func BenchmarkNewLargeTree(b *testing.B) {
	ctx := context.Background()
	leaves := make([][]byte, 10000)
	for i := range leaves {
		leaves[i] = SHA384([]byte{byte(i), byte(i >> 8)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = New(ctx, leaves, WithHashType(HashTypeSHA384))
	}
}

func BenchmarkGenerateProof(b *testing.B) {
	ctx := context.Background()
	leaves := make([][]byte, 1000)
	for i := range leaves {
		leaves[i] = SHA256([]byte{byte(i), byte(i >> 8)})
	}

	tree := New(ctx, leaves, WithHashType(HashTypeSHA256))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tree.GenerateProof(uint32(i % 1000))
	}
}
