// Copyright 2026 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package merkle

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

const (
	// proofVersion is the current version of the proof serialization format.
	proofVersion = 0x01
	// internalNodePrefix is used to distinguish internal node hashes from leaf hashes.
	// This provides protection against second-preimage attacks.
	internalNodePrefix = 0x01
)

// Direction indicates whether a sibling is on the left or right of the current node.
type Direction uint8

const (
	// Left indicates the sibling is on the left side.
	Left Direction = 0
	// Right indicates the sibling is on the right side.
	Right Direction = 1
)

// Sibling represents a sibling hash in the merkle proof path.
type Sibling struct {
	// Direction indicates if this sibling is on the left or right.
	Direction Direction
	// Hash is the hash value of the sibling node.
	Hash []byte
}

// Proof represents a merkle inclusion proof for a specific leaf.
// It contains all the sibling hashes needed to reconstruct the path from leaf to root.
type Proof struct {
	// LeafIndex is the position of the leaf in the original leaves array.
	LeafIndex uint32
	// Siblings is the list of sibling hashes from leaf to root.
	Siblings []Sibling
	// HashType is the hash algorithm used to build the tree.
	HashType HashType
}

// Verify checks if the proof is valid for the given leaf hash and root hash.
// The leaf parameter should be the original leaf hash (before any prefixing).
// Returns true if the proof successfully reconstructs the root from the leaf.
func (p *Proof) Verify(leaf, root []byte) bool {
	if p == nil || len(p.Siblings) == 0 && len(leaf) == 0 {
		return false
	}

	hasher := p.HashType.Hasher()
	current := leaf

	for _, s := range p.Siblings {
		var combined []byte
		if s.Direction == Left {
			// Sibling is on the left, so: hash(prefix || sibling || current)
			combined = make([]byte, 1+len(s.Hash)+len(current))
			combined[0] = internalNodePrefix
			copy(combined[1:], s.Hash)
			copy(combined[1+len(s.Hash):], current)
		} else {
			// Sibling is on the right, so: hash(prefix || current || sibling)
			combined = make([]byte, 1+len(current)+len(s.Hash))
			combined[0] = internalNodePrefix
			copy(combined[1:], current)
			copy(combined[1+len(current):], s.Hash)
		}

		current = hasher(combined)
	}

	return bytes.Equal(current, root)
}

// Serialize converts the proof to a binary format for storage.
//
// Format:
//
//	Byte 0:     Version (0x01)
//	Byte 1:     HashType (0x00=SHA256, 0x01=SHA384, 0x02=SHA512)
//	Byte 2:     Number of siblings (0-255)
//	Bytes 3..N: Siblings data
//
//	For each sibling:
//	  Byte 0:       Direction (0x00=Left, 0x01=Right)
//	  Bytes 1..H:   Hash (H = hash size based on HashType)
func (p *Proof) Serialize() []byte {
	if p == nil {
		return nil
	}

	hashSize := p.HashType.Size()
	size := 3 + len(p.Siblings)*(1+hashSize)
	buf := make([]byte, size)

	buf[0] = proofVersion
	buf[1] = byte(p.HashType)

	siblingCount := len(p.Siblings)
	if siblingCount > 255 {
		siblingCount = 255
	}

	buf[2] = byte(siblingCount) //nolint:gosec // bounds checked above

	offset := 3
	for _, s := range p.Siblings {
		buf[offset] = byte(s.Direction)
		copy(buf[offset+1:], s.Hash)
		offset += 1 + hashSize
	}

	return buf
}

// DeserializeProof reconstructs a Proof from serialized bytes.
// Returns an error if the data is malformed or uses an unsupported version.
func DeserializeProof(data []byte) (*Proof, error) {
	if len(data) < 3 {
		return nil, errors.New("proof data too short: minimum 3 bytes required")
	}

	version := data[0]
	if version != proofVersion {
		return nil, fmt.Errorf("unsupported proof version: %d (expected %d)", version, proofVersion)
	}

	hashType := HashType(data[1])

	hashSize := hashType.Size()
	if hashSize == 0 {
		return nil, fmt.Errorf("invalid hash type: %d", data[1])
	}

	numSiblings := int(data[2])
	expectedSize := 3 + numSiblings*(1+hashSize)

	if len(data) != expectedSize {
		return nil, fmt.Errorf("proof size mismatch: expected %d bytes, got %d", expectedSize, len(data))
	}

	siblings := make([]Sibling, numSiblings)

	offset := 3
	for i := range siblings {
		direction := Direction(data[offset])
		if direction != Left && direction != Right {
			return nil, fmt.Errorf("invalid direction at sibling %d: %d", i, direction)
		}

		siblings[i] = Sibling{
			Direction: direction,
			Hash:      slices.Clone(data[offset+1 : offset+1+hashSize]),
		}
		offset += 1 + hashSize
	}

	return &Proof{
		Siblings: siblings,
		HashType: hashType,
	}, nil
}
