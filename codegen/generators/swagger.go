package generators

import (
	"encoding/json"
	"fmt"
	"os"
)

type swaggerSpec struct {
	Paths       map[string]pathItem `json:"paths"`
	Definitions map[string]*schema  `json:"definitions"`
}

type pathItem struct {
	Post *operation `json:"post"`
}

type operation struct {
	Summary     string              `json:"summary"`
	Description string              `json:"description"`
	OperationID string              `json:"operationId"`
	Deprecated  bool                `json:"deprecated"`
	Responses   map[string]response `json:"responses"`
	Parameters  []parameter         `json:"parameters"`
}

type response struct {
	Schema *schema `json:"schema"`
}

type parameter struct {
	In     string  `json:"in"`
	Schema *schema `json:"schema"`
}

type schema struct {
	Ref                  string             `json:"$ref"`
	Type                 string             `json:"type"`
	Format               string             `json:"format"`
	Description          string             `json:"description"`
	Enum                 []string           `json:"enum"`
	Items                *schema            `json:"items"`
	Properties           map[string]*schema `json:"properties"`
	Required             []string           `json:"required"`
	AdditionalProperties any                `json:"additionalProperties"`
}

func readSpecs(paths []string) ([]*swaggerSpec, error) {
	var specs []*swaggerSpec

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		var spec swaggerSpec
		if err := json.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		specs = append(specs, &spec)
	}

	return specs, nil
}
