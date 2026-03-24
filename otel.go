// Copyright 2026 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package merkle

import "go.opentelemetry.io/otel"

const tracerName = "github.com/hyperscale-stack/merkle"

var tracer = otel.Tracer(tracerName)
