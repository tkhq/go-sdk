package main

import (
	"fmt"
	"os"
	"time"

	"github.com/tkhq/go-sdk/internal/changesets"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dir := changesets.DefaultDir

	pending, err := changesets.LoadPending(dir)
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		fmt.Println("No pending changesets found – nothing to version.")
		return nil
	}

	curVersion, err := changesets.ReadVersion(changesets.VersionFile)
	if err != nil {
		return err
	}

	bump := changesets.MaxBump(pending)
	nextVersion, err := changesets.NextVersion(curVersion, bump)
	if err != nil {
		return err
	}

	if err := changesets.WriteVersion(changesets.VersionFile, nextVersion); err != nil {
		return err
	}

	meta := changesets.ReleaseMeta{
		Version:         nextVersion,
		PreviousVersion: curVersion,
		Created:         time.Now().Format(time.RFC3339),
		Changes:         pending,
	}

	if err := changesets.WriteReleaseMeta(dir, meta); err != nil {
		return err
	}

	fmt.Printf("Current version: %s\n", curVersion)
	fmt.Printf("Bump type:       %s\n", bump)
	fmt.Printf("Next version:    %s\n", nextVersion)
	fmt.Printf("Wrote VERSION and %s\n", changesets.ReleaseMetaFile)

	return nil
}
