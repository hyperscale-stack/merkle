# Merkle

[![CI](https://github.com/hyperscale-stack/merkle/actions/workflows/ci.yml/badge.svg)](https://github.com/hyperscale-stack/merkle/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/hyperscale-stack/merkle.svg)](https://pkg.go.dev/github.com/hyperscale-stack/merkle)
[![Go Report Card](https://goreportcard.com/badge/github.com/hyperscale-stack/merkle)](https://goreportcard.com/report/github.com/hyperscale-stack/merkle)

A production-ready Merkle tree implementation in Go with cryptographic proof generation, verification, and compact binary serialization.

## Features

- **Merkle tree construction** from arbitrary leaf data
- **Inclusion proof generation and verification** with O(1) proof lookup
- **Multiple hash algorithms**: SHA-256, SHA-384, SHA-512
- **Configurable balancing strategies**: duplicate last leaf or static padding for odd leaf counts
- **Compact binary serialization** of proofs for storage and transport
- **Second-preimage attack protection** via internal node prefix
- **OpenTelemetry tracing** for observability
- **Context support** for cancellation and timeouts

## Installation

```bash
go get github.com/hyperscale-stack/merkle
```

Requires **Go 1.25+**.

## Quick Start

```go
package main

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/merkle"
)

func main() {
	ctx := context.Background()

	// Hash your data into leaves
	leaves := [][]byte{
		merkle.SHA256([]byte("alice")),
		merkle.SHA256([]byte("bob")),
		merkle.SHA256([]byte("charlie")),
		merkle.SHA256([]byte("dave")),
	}

	// Build the tree
	tree := merkle.New(ctx, leaves, merkle.WithHashType(merkle.HashTypeSHA256))

	// Get the root hash
	root := tree.RootHash()
	fmt.Printf("Root: %x\n", root)

	// Generate a proof for leaf at index 0
	proof := tree.GenerateProof(0)

	// Verify the proof
	valid := proof.Verify(leaves[0], root)
	fmt.Printf("Proof valid: %v\n", valid)
}
```

## Usage

### Building a Tree

```go
tree := merkle.New(ctx, leaves, merkle.WithHashType(merkle.HashTypeSHA256))
```

### Hash Algorithms

```go
// SHA-256 (default)
tree := merkle.New(ctx, leaves, merkle.WithHashType(merkle.HashTypeSHA256))

// SHA-384
tree := merkle.New(ctx, leaves, merkle.WithHashType(merkle.HashTypeSHA384))

// SHA-512
tree := merkle.New(ctx, leaves, merkle.WithHashType(merkle.HashTypeSHA512))
```

### Balance Strategies

When the number of leaves is odd, you can choose how to balance the tree:

```go
// Duplicate last leaf (default)
tree := merkle.New(ctx, leaves, merkle.WithBalanceStrategy(merkle.DuplicateLastLeaf))

// Pad with a static hash value
tree := merkle.New(ctx, leaves, merkle.WithPaddingValue(merkle.SHA256([]byte("padding"))))
```

### Proofs

Generate an inclusion proof for any leaf, then verify it:

```go
// Generate proof for leaf at index 2
proof := tree.GenerateProof(2)

// Verify against the root
valid := proof.Verify(leaves[2], tree.RootHash())
```

### Proof Serialization

Proofs can be serialized to a compact binary format for storage or network transport:

```go
// Serialize
data := proof.Serialize()

// Deserialize
restored, err := merkle.DeserializeProof(data)
if err != nil {
    log.Fatal(err)
}

// Verify the deserialized proof
valid := restored.Verify(leaf, root)
```

#### Binary Format

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 1 | Version (`0x01`) |
| 1 | 1 | Hash type (`0x00`=SHA-256, `0x01`=SHA-384, `0x02`=SHA-512) |
| 2 | 1 | Number of siblings |
| 3+ | N | Sibling entries: 1 byte direction + H bytes hash |

## API Reference

### Tree

| Function / Method | Description |
|---|---|
| `New(ctx, leaves, opts...)` | Build a tree with proof generation support |
| `tree.RootHash()` | Return the root hash |
| `tree.GenerateProof(index)` | Generate an inclusion proof for a leaf |
| `tree.LeafCount()` | Return the number of original leaves |

### Proof

| Function / Method | Description |
|---|---|
| `proof.Verify(leaf, root)` | Verify the proof against a leaf and root hash |
| `proof.Serialize()` | Serialize the proof to binary |
| `DeserializeProof(data)` | Deserialize a proof from binary |

### Options

| Option | Description |
|---|---|
| `WithHashType(hashType)` | Set the hash algorithm (preferred) |
| `WithBalanceStrategy(strategy)` | Set the balancing strategy for odd leaf counts |
| `WithPaddingValue(value)` | Set a static padding value (implies `PadWithStaticHash`) |

### Hash Types

| Constant | Algorithm | Output Size |
|---|---|---|
| `HashTypeSHA256` | SHA-256 | 32 bytes |
| `HashTypeSHA384` | SHA-384 | 48 bytes |
| `HashTypeSHA512` | SHA-512 | 64 bytes |

## Security

- **Internal node prefix** (`0x01`): Leaf and internal node hashes use different domains, protecting against second-preimage attacks.
- **Proof direction tracking**: Each sibling records whether it is on the left or right, preventing proof reordering.

## Development

```bash
# Run tests with race detection and coverage
make test

# Run linter
make lint

# Generate coverage report
make coverage-html
```

## License

MIT License - Copyright (c) Axel Etcheverry.
