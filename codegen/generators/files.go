package generators

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"sort"
	"strings"

	"github.com/tkhq/go-sdk/v2/internal/fileperms"
)

func writeGo(path string, src string) error {
	formatted, err := format.Source([]byte(src))
	if err != nil {
		var lines bytes.Buffer
		for i, line := range strings.Split(src, "\n") {
			fmt.Fprintf(&lines, "%4d: %s\n", i+1, line)
		}

		return fmt.Errorf("format %s: %w\n%s", path, err, lines.String())
	}

	return os.WriteFile(path, formatted, fileperms.File)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
