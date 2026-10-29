// Command gen regenerates gen/ from the proto schema. Run it from the proto
// directory (make generate-proto does); it requires the buf CLI.
//
// It compiles schema/ with buf, then strips the google.api and openapiv2
// annotations before invoking protoc-gen-go. The annotations only describe
// the JSON API for documentation tooling — the wire format these packages
// exist for does not depend on them. Stripping them matters for two reasons:
//
//   - Generating private copies of the annotation protos would re-register
//     the global google.api.* and grpc.gateway.protoc_gen_openapiv2.options.*
//     names and extension numbers, so any binary that also links the
//     canonical packages (google.golang.org/genproto, grpc-gateway) would
//     panic at init with a protobuf namespace conflict.
//   - Importing the canonical packages instead would make this module
//     depend on genproto and grpc-gateway, dragging a large dependency
//     graph into every consumer of a package that only decodes signed bytes.
//
// With the annotations stripped, the generated packages are self-contained
// and depend on nothing beyond google.golang.org/protobuf.
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

const (
	// Path prefix of the vendored annotation protos inside the schema module.
	vendorPrefix = "vendor/"
	// Go module path the generated packages live under.
	genModule = "github.com/tkhq/go-sdk/proto/gen"
	// Output directory, relative to the proto directory.
	outDir = "gen"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	if _, err := os.Stat("buf.yaml"); err != nil {
		return fmt.Errorf("must run from the proto directory (buf.yaml not found): %w", err)
	}

	raw, err := output("buf", "build", "--as-file-descriptor-set", "-o", "-#format=binpb")
	if err != nil {
		return err
	}

	// This binary links no annotation packages, so every annotation extension
	// (google.api.field_behavior, the openapiv2 options, ...) is an unknown
	// field here and DiscardUnknown drops them all. Standard options such as
	// go_package are known fields and survive.
	fds := new(descriptorpb.FileDescriptorSet)
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, fds); err != nil {
		return fmt.Errorf("unmarshal descriptor set: %w", err)
	}

	req := &pluginpb.CodeGeneratorRequest{
		Parameter: proto.String("module=" + genModule),
	}
	for _, file := range fds.GetFile() {
		name := file.GetName()
		if strings.HasPrefix(name, vendorPrefix) {
			continue
		}
		if len(file.GetPublicDependency()) > 0 || len(file.GetWeakDependency()) > 0 {
			return fmt.Errorf("%s: public/weak imports are not supported by the vendor-import filtering", name)
		}
		deps := file.GetDependency()[:0]
		for _, dep := range file.GetDependency() {
			if !strings.HasPrefix(dep, vendorPrefix) {
				deps = append(deps, dep)
			}
		}
		file.Dependency = deps
		file.SourceCodeInfo = nil
		if !strings.HasPrefix(name, "google/protobuf/") {
			// Well-known types keep their upstream go_package; everything
			// else is rehomed under this module (the synced files point at
			// mono's internal gen tree).
			if file.Options == nil {
				file.Options = new(descriptorpb.FileOptions)
			}
			file.Options.GoPackage = proto.String(genModule + "/" + path.Dir(name))
			req.FileToGenerate = append(req.FileToGenerate, name)
		}
		req.ProtoFile = append(req.ProtoFile, file)
	}

	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal codegen request: %w", err)
	}
	respBytes, err := outputStdin(reqBytes, "go", "tool", "protoc-gen-go")
	if err != nil {
		return err
	}
	resp := new(pluginpb.CodeGeneratorResponse)
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		return fmt.Errorf("unmarshal codegen response: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("protoc-gen-go: %s", resp.GetError())
	}

	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	for _, file := range resp.GetFile() {
		dst := filepath.Join(outDir, filepath.FromSlash(file.GetName()))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(file.GetContent()), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func output(name string, args ...string) ([]byte, error) {
	return outputStdin(nil, name, args...)
}

func outputStdin(stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}
