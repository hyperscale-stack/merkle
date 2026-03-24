// Copyright 2026 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package merkle

import (
	"crypto/sha256"
	"crypto/sha512"
)

// Hasher defines a hash function signature that takes data and returns its hash.
type Hasher func(data []byte) []byte

// SHA256 is a Hasher that computes SHA-256 hashes (32 bytes output).
var SHA256 Hasher = func(data []byte) []byte {
	sum := sha256.Sum256(data)

	return sum[:]
}

// SHA384 is a Hasher that computes SHA-384 hashes (48 bytes output).
var SHA384 Hasher = func(data []byte) []byte {
	sum := sha512.Sum384(data)

	return sum[:]
}

// SHA512 is a Hasher that computes SHA-512 hashes (64 bytes output).
var SHA512 Hasher = func(data []byte) []byte {
	sum := sha512.Sum512(data)

	return sum[:]
}

// HashType represents the type of hash algorithm used in the merkle tree.
type HashType uint8

const (
	// HashTypeSHA256 represents SHA-256 hash algorithm (32 bytes).
	HashTypeSHA256 HashType = iota
	// HashTypeSHA384 represents SHA-384 hash algorithm (48 bytes).
	HashTypeSHA384
	// HashTypeSHA512 represents SHA-512 hash algorithm (64 bytes).
	HashTypeSHA512
)

// Size returns the output size in bytes for the hash type.
func (h HashType) Size() int {
	switch h {
	case HashTypeSHA256:
		return 32
	case HashTypeSHA384:
		return 48
	case HashTypeSHA512:
		return 64
	default:
		return 0
	}
}

// Hasher returns the Hasher function for this HashType.
func (h HashType) Hasher() Hasher {
	switch h {
	case HashTypeSHA256:
		return SHA256
	case HashTypeSHA384:
		return SHA384
	case HashTypeSHA512:
		return SHA512
	default:
		return SHA384 // Default to SHA384
	}
}

// String returns the string representation of the HashType.
func (h HashType) String() string {
	switch h {
	case HashTypeSHA256:
		return "SHA-256"
	case HashTypeSHA384:
		return "SHA-384"
	case HashTypeSHA512:
		return "SHA-512"
	default:
		return "unknown"
	}
}
