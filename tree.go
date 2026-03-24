// Copyright 2026 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package merkle

import (
	"context"
)

// BalanceStrategy defines how to handle odd numbers of nodes when building the tree.
type BalanceStrategy int

const (
	// DuplicateLastLeaf duplicates the last leaf when there's an odd number of nodes.
	DuplicateLastLeaf BalanceStrategy = iota
	// PadWithStaticHash uses a static padding value when there's an odd number of nodes.
	PadWithStaticHash
)

// Config holds configuration options for building a merkle tree.
type Config struct {
	BalanceStrategy BalanceStrategy
	PaddingValue    []byte // Used only if BalanceStrategy is PadWithStaticHash
	HashFunc        Hasher
	HashType        HashType
}

// Option is a function that modifies Config.
type Option func(o *Config)

// WithBalanceStrategy sets the balance strategy for handling odd node counts.
func WithBalanceStrategy(strategy BalanceStrategy) Option {
	return func(o *Config) {
		o.BalanceStrategy = strategy
	}
}

// WithPaddingValue sets a static padding value and enables PadWithStaticHash strategy.
func WithPaddingValue(value []byte) Option {
	return func(o *Config) {
		o.PaddingValue = value
		o.BalanceStrategy = PadWithStaticHash
	}
}

// WithHashFunc sets the hash function to use.
//
// Deprecated: Use WithHashType instead for better type safety and proof serialization.
func WithHashFunc(hashFunc Hasher) Option {
	return func(o *Config) {
		o.HashFunc = hashFunc
	}
}

// WithHashType sets the hash type to use.
// This is the preferred way to set the hash function as it also sets the HashType
// which is needed for proof serialization.
func WithHashType(hashType HashType) Option {
	return func(o *Config) {
		o.HashType = hashType
		o.HashFunc = hashType.Hasher()
	}
}

// Tree represents a merkle tree with optional proof generation capabilities.
type Tree struct {
	Leaves     [][]byte
	Root       *Node
	config     *Config
	proofPaths [][]Sibling // Pre-computed proof paths for each leaf
}

// RootHash returns the root hash of the tree.
// Returns nil if the tree is empty.
func (t *Tree) RootHash() []byte {
	if t == nil || t.Root == nil {
		return nil
	}

	return t.Root.Value
}

// GenerateProof creates a merkle proof for the leaf at the given index.
// Returns nil if the index is out of bounds or if proof paths were not computed.
func (t *Tree) GenerateProof(index uint32) *Proof {
	if t == nil || int(index) >= len(t.proofPaths) {
		return nil
	}

	return &Proof{
		LeafIndex: index,
		Siblings:  t.proofPaths[index],
		HashType:  t.config.HashType,
	}
}

// LeafCount returns the number of original leaves (excluding duplicated/padded leaves).
func (t *Tree) LeafCount() int {
	if t == nil {
		return 0
	}

	return len(t.proofPaths)
}

// New creates a new merkle tree from the given leaves with proof generation support.
// This is the preferred constructor as it enables GenerateProof() functionality.
func New(ctx context.Context, leaves [][]byte, opts ...Option) *Tree {
	_, span := tracer.Start(ctx, "merkle.New")
	defer span.End()

	if len(leaves) == 0 {
		return nil
	}

	config := &Config{
		BalanceStrategy: DuplicateLastLeaf,
		HashType:        HashTypeSHA256,
		HashFunc:        SHA256,
	}

	for _, opt := range opts {
		opt(config)
	}

	// Ensure HashFunc is set if only HashType was specified
	if config.HashFunc == nil {
		config.HashFunc = config.HashType.Hasher()
	}

	originalLeafCount := len(leaves)

	// Initialize proof paths for each original leaf
	proofPaths := make([][]Sibling, originalLeafCount)
	for i := range proofPaths {
		proofPaths[i] = make([]Sibling, 0)
	}

	// leafIndices tracks which original leaf indices are descendants of each node
	// leafIndices[i] contains the set of original leaf indices that descend from node i
	type nodeInfo struct {
		node        *Node
		leafIndices []int
	}

	// Build leaf nodes
	currentLevel := make([]nodeInfo, 0, (len(leaves)+1)/2)

	for i := 0; i < len(leaves); i += 2 {
		leftLeaf := leaves[i]
		leftNode := NewNode(nil, nil, leftLeaf, config.HashFunc)
		leftIndices := []int{i}

		var rightNode *Node

		var rightIndices []int

		if i+1 < len(leaves) {
			// Normal case: we have a right sibling
			rightNode = NewNode(nil, nil, leaves[i+1], config.HashFunc)
			rightIndices = []int{i + 1}
		} else {
			// Odd number of leaves: handle balancing
			switch config.BalanceStrategy {
			case DuplicateLastLeaf:
				rightNode = NewNode(nil, nil, leftLeaf, config.HashFunc)
			case PadWithStaticHash:
				rightNode = NewNode(nil, nil, config.PaddingValue, config.HashFunc)
			}
			// No right indices since it's a duplicate/padding
			rightIndices = []int{}
		}

		// Record siblings for proof paths
		// Left child gets right sibling, right child gets left sibling
		for _, idx := range leftIndices {
			proofPaths[idx] = append(proofPaths[idx], Sibling{
				Direction: Right,
				Hash:      rightNode.Value,
			})
		}

		for _, idx := range rightIndices {
			proofPaths[idx] = append(proofPaths[idx], Sibling{
				Direction: Left,
				Hash:      leftNode.Value,
			})
		}

		// Create parent node with internal node prefix for security
		parentValue := hashInternal(leftNode.Value, rightNode.Value, config.HashFunc)
		parentNode := &Node{
			Left:  leftNode,
			Right: rightNode,
			Value: parentValue,
		}

		// Merge leaf indices
		combined := make([]int, 0, len(leftIndices)+len(rightIndices))
		combined = append(combined, leftIndices...)
		combined = append(combined, rightIndices...)
		currentLevel = append(currentLevel, nodeInfo{node: parentNode, leafIndices: combined})
	}

	// Build upper levels
	for len(currentLevel) > 1 {
		nextLevel := make([]nodeInfo, 0, (len(currentLevel)+1)/2)

		for i := 0; i < len(currentLevel); i += 2 {
			leftInfo := currentLevel[i]

			var rightInfo nodeInfo
			if i+1 < len(currentLevel) {
				rightInfo = currentLevel[i+1]
			} else {
				// Odd number of nodes at this level: duplicate last node
				rightInfo = nodeInfo{
					node:        leftInfo.node,
					leafIndices: []int{}, // No new leaves for duplicated node
				}
			}

			// Record siblings for proof paths
			for _, idx := range leftInfo.leafIndices {
				proofPaths[idx] = append(proofPaths[idx], Sibling{
					Direction: Right,
					Hash:      rightInfo.node.Value,
				})
			}

			for _, idx := range rightInfo.leafIndices {
				proofPaths[idx] = append(proofPaths[idx], Sibling{
					Direction: Left,
					Hash:      leftInfo.node.Value,
				})
			}

			// Create parent node - always hash even when duplicated for consistency
			parentValue := hashInternal(leftInfo.node.Value, rightInfo.node.Value, config.HashFunc)

			parentNode := &Node{
				Left:  leftInfo.node,
				Right: rightInfo.node,
				Value: parentValue,
			}

			combined := make([]int, 0, len(leftInfo.leafIndices)+len(rightInfo.leafIndices))
			combined = append(combined, leftInfo.leafIndices...)
			combined = append(combined, rightInfo.leafIndices...)
			nextLevel = append(nextLevel, nodeInfo{node: parentNode, leafIndices: combined})
		}

		currentLevel = nextLevel
	}

	return &Tree{
		Leaves:     leaves,
		Root:       currentLevel[0].node,
		config:     config,
		proofPaths: proofPaths,
	}
}

// hashInternal computes hash of two child values with internal node prefix.
// This provides protection against second-preimage attacks.
func hashInternal(left, right []byte, hasher Hasher) []byte {
	combined := make([]byte, 1+len(left)+len(right))
	combined[0] = internalNodePrefix
	copy(combined[1:], left)
	copy(combined[1+len(left):], right)

	return hasher(combined)
}

// Build creates a merkle tree from the given leaves.
// This function is kept for backward compatibility.
//
// Deprecated: Use New() instead for proof generation support.
func Build(ctx context.Context, leaves [][]byte, opts ...Option) *Tree {
	_, span := tracer.Start(ctx, "merkle.Build")
	defer span.End()

	if len(leaves) == 0 {
		return nil
	}

	config := &Config{
		BalanceStrategy: DuplicateLastLeaf,
		HashFunc:        SHA256, // Default hash function
	}

	for _, opt := range opts {
		opt(config)
	}

	treeNodes := make([]*Node, 0)

	var duplicatedLeaf []byte

	for _, hashPair := range splitPairs(leaves) {
		left := NewNode(nil, nil, hashPair[0], config.HashFunc)

		var right *Node

		switch {
		case len(hashPair) > 1:
			right = NewNode(nil, nil, hashPair[1], config.HashFunc)
		case config.BalanceStrategy == DuplicateLastLeaf:
			right = NewNode(nil, nil, hashPair[0], config.HashFunc)
			duplicatedLeaf = hashPair[0]
		case config.BalanceStrategy == PadWithStaticHash:
			right = NewNode(nil, nil, config.PaddingValue, config.HashFunc)
			duplicatedLeaf = config.PaddingValue
		}

		treeNodes = append(treeNodes, NewNode(left, right, nil, config.HashFunc))
	}

	for len(treeNodes) > 1 {
		var newLevel []*Node

		for i := 0; i < len(treeNodes); i += 2 {
			right := (*Node)(nil)

			if i+1 < len(treeNodes) {
				right = treeNodes[i+1]
			}

			newLevel = append(newLevel, NewNode(treeNodes[i], right, nil, config.HashFunc))
		}

		treeNodes = newLevel
	}

	if duplicatedLeaf != nil {
		// If we have a duplicated leaf, we need to add it as a leaf
		// to ensure the tree is balanced.
		leaves = append(leaves, duplicatedLeaf)
	}

	return &Tree{
		Root:   treeNodes[0],
		Leaves: leaves,
		config: config,
	}
}

func splitPairs(hashes [][]byte) [][]([]byte) {
	var res [][]([]byte)

	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			res = append(res, [][]byte{hashes[i], hashes[i+1]})
		} else {
			res = append(res, [][]byte{hashes[i]})
		}
	}

	return res
}
