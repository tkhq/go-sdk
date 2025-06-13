// This script tweaks our Swagger spec JSON file by adding
// `"x-nullable": true` to any boolean properties that are not marked as required.
//
// In Go, a non-pointer `bool` with `omitempty` will be omitted from JSON output
// if its value is `false`. This causes issues when the field needs to be explicitly
// set to `false` in a request, such as overriding a default of `true`.
//
// By adding `"x-nullable": true"` to optional boolean fields in the Swagger spec,
// go-swagger will generate `*bool` fields instead of `bool`, which fixes this issue.
package main

import (
	"encoding/json"

	"log"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s <in.json> <out.json>", os.Args[0])
	}
	inPath, outPath := os.Args[1], os.Args[2]

	// load file
	raw, err := os.ReadFile(inPath)
	if err != nil {
		log.Fatalf("read %s: %v", inPath, err)
	}

	var spec map[string]interface{}
	if err := json.Unmarshal(raw, &spec); err != nil {
		log.Fatalf("unmarshal: %v", err)
	}

	// patch definitions
	if defs, ok := spec["definitions"].(map[string]interface{}); ok {
		for _, v := range defs {
			if model, ok := v.(map[string]interface{}); ok {
				// collect required names
				reqSet := map[string]struct{}{}
				if arr, ok := model["required"].([]interface{}); ok {
					for _, x := range arr {
						if s, ok := x.(string); ok {
							reqSet[s] = struct{}{}
						}
					}
				}
				// walk properties
				if props, ok := model["properties"].(map[string]interface{}); ok {
					for name, pv := range props {
						if prop, ok := pv.(map[string]interface{}); ok {
							// type == boolean && not required
							if prop["type"] == "boolean" {
								if _, req := reqSet[name]; !req {
									prop["x-nullable"] = true
								}
							}
						}
					}
				}
			}
		}
	}

	// write back
	outRaw, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(outPath, outRaw, 0644); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
}
