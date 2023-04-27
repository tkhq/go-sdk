// Package util provides convenience utilities for interacting with the API.
package util

import (
	"fmt"
	"time"
)

// RequestTimestamp returns a timestamp formatted for inclusion in a request.
func RequestTimestamp() *string {
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())

	return &ts
}
