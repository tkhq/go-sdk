package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/tkhq/go-sdk/internal/changesets"
)

const changelogHeader = "# CHANGELOG"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dir := changesets.DefaultDir

	meta, err := changesets.ReadReleaseMeta(dir)
	if err != nil {
		return fmt.Errorf("read release meta: %w", err)
	}
	if meta.Version == "" {
		return fmt.Errorf("release meta missing version")
	}
	if len(meta.Changes) == 0 {
		fmt.Println("No changes in release meta; nothing to add to changelog.")
		return nil
	}

	date := changesets.TodayDate()
	section := buildReleaseSection(meta.Version, meta.PreviousVersion, date, meta.Changes)

	existing, err := os.ReadFile(changesets.ChangelogFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read existing changelog: %w", err)
	}
	newContent := mergeChangelog(string(existing), section)

	// 0o644 => -rw-r--r-- : owner can read/write, group/others read-only.
	if err := os.WriteFile(changesets.ChangelogFile, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("write changelog: %w", err)
	}

	// Cleanup processed changesets
	if err := changesets.DeleteProcessedChanges(dir, meta); err != nil {
		return fmt.Errorf("cleanup changesets: %w", err)
	}

	fmt.Printf("Updated %s with version %s (%s)\n", changesets.ChangelogFile, meta.Version, date)
	return nil
}

func buildReleaseSection(version, previousVersion, date string, changes []changesets.Change) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "## %s — %s\n", version, date)

	// Group by bump type
	byBump := map[string][]changesets.Change{
		"patch": {},
		"minor": {},
		"major": {},
	}

	for _, ch := range changes {
		switch ch.Bump {
		case "major", "minor", "patch":
			byBump[ch.Bump] = append(byBump[ch.Bump], ch)
		default:
			byBump["patch"] = append(byBump["patch"], ch)
		}
	}

	type sectionInfo struct {
		key     string
		heading string
	}

	order := []sectionInfo{
		{"patch", "Patch Changes"},
		{"minor", "Minor Changes"},
		{"major", "Major Changes"},
	}

	for _, sec := range order {
		list := byBump[sec.key]

		if len(list) == 0 {
			continue
		}

		fmt.Fprintf(&sb, "### %s\n", sec.heading)

		for _, ch := range list {
			// Use the changeset note as the bullet line.
			fmt.Fprintf(&sb, "- %s\n", ch.Note)
		}
	}

	sb.WriteString("\n")

	// Comparison link
	fmt.Fprintf(&sb, "### [v%s ... v%s](https://github.com/tkhq/go-sdk/compare/v%s...v%s)\n", previousVersion, version, previousVersion, version)

	return sb.String()
}

func mergeChangelog(existing, newSection string) string {
	if strings.TrimSpace(existing) == "" {
		// Fresh file
		return changelogHeader + "\n\n" + newSection
	}

	trimmed := strings.TrimSpace(existing)

	if !strings.HasPrefix(trimmed, changelogHeader) {
		// No header: prepend one
		return changelogHeader + "\n\n" + newSection + strings.TrimPrefix("\n"+existing, "\n")
	}

	// Assume first line is "# CHANGELOG"
	lines := strings.SplitN(existing, "\n", 2)
	header := lines[0]
	rest := ""

	if len(lines) == 2 {
		rest = lines[1]
	}

	rest = strings.TrimLeft(rest, "\n")

	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString("\n\n")
	sb.WriteString(newSection)

	if strings.TrimSpace(rest) != "" {
		sb.WriteString(restPrefix(rest))
		sb.WriteString(rest)
	}

	return sb.String()
}

func restPrefix(rest string) string {
	if strings.HasPrefix(rest, "## ") {
		return "\n"
	}

	return "\n\n"
}
