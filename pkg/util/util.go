// Package util provides convenience utilities for interacting with the API.
package util

import (
	"strconv"
	"time"
)

// RequestTimestamp returns a timestamp formatted for inclusion in a request.
func RequestTimestamp() *string {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)

	return &ts
}
