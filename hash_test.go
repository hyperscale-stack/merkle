// Copyright 2026 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package merkle

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hex.EncodeToString(SHA256([]byte("hello"))))
	assert.Equal(t, "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f", hex.EncodeToString(SHA384([]byte("hello"))))
}

func TestSHA512(t *testing.T) {
	// Expected SHA512 of "hello"
	expected := "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
	result := hex.EncodeToString(SHA512([]byte("hello")))
	assert.Equal(t, expected, result)
	assert.Equal(t, 64, len(SHA512([]byte("hello"))))
}

func TestHashTypeSize(t *testing.T) {
	tests := []struct {
		name     string
		hashType HashType
		expected int
	}{
		{"SHA256", HashTypeSHA256, 32},
		{"SHA384", HashTypeSHA384, 48},
		{"SHA512", HashTypeSHA512, 64},
		{"Invalid", HashType(99), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.hashType.Size())
		})
	}
}

func TestHashTypeHasher(t *testing.T) {
	input := []byte("test data")

	t.Run("SHA256 hasher", func(t *testing.T) {
		hasher := HashTypeSHA256.Hasher()
		result := hasher(input)
		expected := SHA256(input)
		assert.Equal(t, expected, result)
		assert.Equal(t, 32, len(result))
	})

	t.Run("SHA384 hasher", func(t *testing.T) {
		hasher := HashTypeSHA384.Hasher()
		result := hasher(input)
		expected := SHA384(input)
		assert.Equal(t, expected, result)
		assert.Equal(t, 48, len(result))
	})

	t.Run("SHA512 hasher", func(t *testing.T) {
		hasher := HashTypeSHA512.Hasher()
		result := hasher(input)
		expected := SHA512(input)
		assert.Equal(t, expected, result)
		assert.Equal(t, 64, len(result))
	})

	t.Run("Invalid defaults to SHA384", func(t *testing.T) {
		hasher := HashType(99).Hasher()
		result := hasher(input)
		expected := SHA384(input)
		assert.Equal(t, expected, result)
	})
}

func TestHashTypeString(t *testing.T) {
	tests := []struct {
		hashType HashType
		expected string
	}{
		{HashTypeSHA256, "SHA-256"},
		{HashTypeSHA384, "SHA-384"},
		{HashTypeSHA512, "SHA-512"},
		{HashType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.hashType.String())
		})
	}
}
