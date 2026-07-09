package generators

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tkhq/go-sdk/v2/internal/fileperms"
)

// Options configures SDK code generation.
type Options struct {
	PublicSwaggerPath    string
	AuthProxySwaggerPath string
	ActivitiesPath       string
	OutDir               string
	AllVersions          bool
}

// Generate writes generated SDK client and type files.
func Generate(opts Options) ([]string, error) {
	specs, err := readSpecs([]string{opts.PublicSwaggerPath, opts.AuthProxySwaggerPath})
	if err != nil {
		return nil, err
	}

	var cfg *activitiesConfig

	if opts.ActivitiesPath == "" {
		return nil, fmt.Errorf("activities config path is required")
	}

	cfg, err = readActivitiesConfig(opts.ActivitiesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read activities config: %w", err)
	}

	g := newGenerator(specs, cfg, opts.AllVersions)
	g.collectOperations()

	if err := os.MkdirAll(opts.OutDir, fileperms.Dir); err != nil {
		return nil, err
	}

	files := map[string]string{
		"client_gen.go": g.generateClient(),
		"types_gen.go":  g.generateModels(),
	}

	written := make([]string, 0, len(files))
	for _, name := range sortedKeys(files) {
		path := filepath.Join(opts.OutDir, name)
		if err := writeGo(path, files[name]); err != nil {
			return nil, err
		}

		written = append(written, path)
	}

	return written, nil
}
