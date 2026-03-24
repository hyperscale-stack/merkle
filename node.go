// Copyright 2026 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package merkle

type Node struct {
	Left  *Node
	Right *Node
	Value []byte
}

func NewNode(left, right *Node, value []byte, hash Hasher) *Node {
	if value != nil {
		return &Node{
			Value: value,
		}
	}

	node := &Node{
		Left:  left,
		Right: right,
	}

	if right == nil {
		node.Value = left.Value
	} else {
		node.Value = hash(append(left.Value, right.Value...))
	}

	return node
}
