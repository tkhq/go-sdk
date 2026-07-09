package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tkhq/go-sdk/v2/codegen/generators"
)

func main() {
	publicSwagger := flag.String("swagger", defaultInputPath("codegen/inputs/public_api.swagger.json", "inputs/public_api.swagger.json"), "path to public API swagger")
	authProxySwagger := flag.String("auth-proxy-swagger", defaultInputPath("codegen/inputs/auth_proxy.swagger.json", "inputs/auth_proxy.swagger.json"), "path to auth proxy swagger")
	activitiesPath := flag.String("activities", defaultInputPath("codegen/inputs/activities.json", "inputs/activities.json"), "path to activities config JSON")
	outDir := flag.String("out", ".", "generated Go package output directory")
	all := flag.Bool("all", false, "generate methods for all historical activity versions in addition to the current ones")

	flag.Parse()

	written, err := generators.Generate(generators.Options{
		PublicSwaggerPath:    *publicSwagger,
		AuthProxySwaggerPath: *authProxySwagger,
		ActivitiesPath:       *activitiesPath,
		OutDir:               *outDir,
		AllVersions:          *all,
	})
	if err != nil {
		fatal(err)
	}

	for _, path := range written {
		fmt.Printf("wrote %s\n", path)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "codegen: %v\n", err)
	os.Exit(1)
}

func defaultInputPath(rootPath string, modulePath string) string {
	if _, err := os.Stat(rootPath); err == nil {
		return rootPath
	}

	return modulePath
}
