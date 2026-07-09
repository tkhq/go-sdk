// Package changesets provides utilities for managing changesets and releases.
package changesets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tkhq/go-sdk/v2/internal/fileperms"
)

const (
	DefaultDir      = ".changesets"
	VersionFile     = "VERSION"
	GoWorkFile      = "go.work"
	ChangelogFile   = "CHANGELOG.md"
	ChangelogHeader = "# CHANGELOG"

	BumpMajor = "major"
	BumpMinor = "minor"
	BumpPatch = "patch"

	ModuleCrypto   = "crypto"
	ModuleEncoding = "encoding"
)

// ModuleOption represents a selectable module.
type ModuleOption struct {
	Key   string // "" for root module
	Label string
}

// KnownModules is the ordered list of modules in this repo.
var KnownModules = []ModuleOption{
	{Key: "", Label: "root (go-sdk)"},
	{Key: ModuleCrypto, Label: ModuleCrypto},
	{Key: ModuleEncoding, Label: ModuleEncoding},
}

// PublishConfig holds tag and module-path info for publishing a module.
type PublishConfig struct {
	TagPrefix  string
	ModulePath string
}

// PublishConfigFor returns the publish config for a given module key.
func PublishConfigFor(module string) PublishConfig {
	switch module {
	case ModuleCrypto:
		return PublishConfig{TagPrefix: "crypto/v", ModulePath: "github.com/tkhq/go-sdk/crypto"}
	case ModuleEncoding:
		return PublishConfig{TagPrefix: "encoding/v", ModulePath: "github.com/tkhq/go-sdk/encoding"}
	default:
		return PublishConfig{TagPrefix: "v", ModulePath: "github.com/tkhq/go-sdk/v2"}
	}
}

// ModulePaths resolves file paths for a given module. Pass "" for the root module.
type ModulePaths struct {
	ChangesetDir  string
	VersionFile   string
	ChangelogFile string
}

func PathsFor(module string) ModulePaths {
	if module == "" {
		return ModulePaths{
			ChangesetDir:  DefaultDir,
			VersionFile:   VersionFile,
			ChangelogFile: ChangelogFile,
		}
	}
	return ModulePaths{
		ChangesetDir:  DefaultDir, // all changesets live in root .changesets/
		VersionFile:   filepath.Join(module, VersionFile),
		ChangelogFile: filepath.Join(module, ChangelogFile),
	}
}

// GoModFor returns the go.mod path for a module key ("" = root).
func GoModFor(module string) string {
	if module == "" {
		return "go.mod"
	}
	return filepath.Join(module, "go.mod")
}

// Change represents one changeset entry.
type Change struct {
	File   string `json:"file"`
	Module string `json:"module"` // "" means root; matches KnownModules Key
	Title  string `json:"title"`
	Bump   string `json:"bump"` // "patch" | "minor" | "major"
	Date   string `json:"date"` // "YYYY-MM-DD"
	Note   string `json:"note"` // full markdown body
}

// LoadPending reads all .md files in .changesets (except those starting with "_")
// and parses their frontmatter + body into Change structs.
func LoadPending(dir string) ([]Change, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	out := make([]Change, 0, len(entries))

	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		name := e.Name()

		if strings.HasPrefix(name, "_") || !strings.HasSuffix(name, ".md") {
			continue
		}

		path := filepath.Join(dir, name)

		ch, err := parseChangeFile(path)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}

		ch.File = path
		out = append(out, ch)
	}

	return out, nil
}

// GroupByModule splits a slice of changes into per-module buckets.
func GroupByModule(changes []Change) map[string][]Change {
	out := make(map[string][]Change)
	for _, ch := range changes {
		out[ch.Module] = append(out[ch.Module], ch)
	}
	return out
}

//nolint:gocyclo // frontmatter parsing requires sequential validation
func parseChangeFile(path string) (Change, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Change{}, err
	}

	s := strings.TrimSpace(string(data))

	if !strings.HasPrefix(s, "---") {
		return Change{}, fmt.Errorf("missing frontmatter '---' at start")
	}

	parts := strings.SplitN(s, "---", 3)

	if len(parts) < 3 {
		return Change{}, fmt.Errorf("invalid frontmatter structure")
	}

	front := strings.TrimSpace(parts[1])
	body := strings.TrimSpace(parts[2])

	var ch Change

	for _, line := range strings.Split(front, "\n") {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		colon := strings.IndexByte(line, ':')

		if colon <= 0 {
			continue
		}

		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		val = strings.Trim(val, `"`) // strip optional quotes

		switch key {
		case "module":
			if val == "root" {
				ch.Module = ""
			} else {
				ch.Module = val
			}
		case "title":
			ch.Title = val
		case "bump":
			ch.Bump = val
		case "date":
			ch.Date = val
		}
	}

	ch.Note = body

	if ch.Title == "" {
		return Change{}, fmt.Errorf("missing title in frontmatter")
	}

	if ch.Bump == "" {
		ch.Bump = "patch"
	}

	return ch, nil
}

// MaxBump returns the highest bump level across all changes.
func MaxBump(changes []Change) string {
	level := 0

	for _, c := range changes {
		l := bumpLevel(c.Bump)
		if l > level {
			level = l
		}
	}

	switch level {
	case 3:
		return BumpMajor
	case 2:
		return BumpMinor
	default:
		return BumpPatch
	}
}

func bumpLevel(b string) int {
	switch b {
	case BumpMajor:
		return 3
	case BumpMinor:
		return 2
	default:
		return 1
	}
}

// NextVersion applies the bump to a semver string "X.Y.Z".
func NextVersion(current, bump string) (string, error) {
	parts := strings.Split(strings.TrimSpace(current), ".")

	if len(parts) != 3 {
		return "", fmt.Errorf("invalid version %q, expected X.Y.Z", current)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", err
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", err
	}

	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", err
	}

	switch bump {
	case BumpMajor:
		major++
		minor = 0
		patch = 0
	case BumpMinor:
		minor++
		patch = 0
	default: // patch
		patch++
	}

	return fmt.Sprintf("%d.%d.%d", major, minor, patch), nil
}

// ReadVersion reads VERSION file from repo root
func ReadVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("no version file found")
		}
		return "", err
	}

	v := strings.TrimSpace(string(data))

	if v == "" {
		return "", fmt.Errorf("version file is empty")
	}

	return strings.TrimPrefix(v, "v"), nil
}

func WriteVersion(path, version string) error {
	return os.WriteFile(path, []byte("v"+version+"\n"), fileperms.File)
}

// UpdateModuleRequires rewrites the inter-module `require` directives in every
// module's go.mod so each points at the current VERSION of the module it
// depends on (crypto → encoding, root → crypto + encoding). This keeps the
// published module graph consistent with the VERSION files: without it the
// requires would keep the local-dev placeholder (v0.0.0, only resolvable via
// the go.work workspace / replace directives) and break for consumers.
// It returns the paths of the go.mod files it modified.
func UpdateModuleRequires() ([]string, error) {
	// Resolve the current version string (e.g. "v0.1.0") for each module.
	versions, err := currentModuleVersions()
	if err != nil {
		return nil, err
	}

	var changed []string
	for _, dependent := range KnownModules {
		goModPath := GoModFor(dependent.Key)
		data, err := os.ReadFile(goModPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", goModPath, err)
		}

		updated := string(data)
		fileChanged := false
		for _, dep := range KnownModules {
			if dep.Key == dependent.Key {
				continue // a module never requires itself
			}
			modulePath := PublishConfigFor(dep.Key).ModulePath
			next, replaced := replaceRequireVersion(updated, modulePath, versions[dep.Key])
			if replaced {
				updated = next
				fileChanged = true
			}
		}

		if fileChanged {
			if err := os.WriteFile(goModPath, []byte(updated), fileperms.File); err != nil {
				return nil, fmt.Errorf("write %s: %w", goModPath, err)
			}
			changed = append(changed, goModPath)
		}
	}
	return changed, nil
}

// UpdateWorkspaceReplaces rewrites go.work's version-specific replace directives
// for nested modules to the current VERSION values. This lets release-branch CI
// build the release commit before those versions have been tagged publicly.
func UpdateWorkspaceReplaces() (string, error) {
	versions, err := currentModuleVersions()
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(GoWorkFile)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", GoWorkFile, err)
	}

	updated := string(data)
	changed := false
	for _, mod := range KnownModules {
		if mod.Key == "" {
			continue
		}

		modulePath := PublishConfigFor(mod.Key).ModulePath
		localPath := "./" + mod.Key
		next, replaced := replaceWorkspaceReplaceVersion(updated, modulePath, versions[mod.Key], localPath)
		updated = next
		changed = changed || replaced
	}

	if !changed {
		return "", nil
	}

	if err := os.WriteFile(GoWorkFile, []byte(updated), fileperms.File); err != nil {
		return "", fmt.Errorf("write %s: %w", GoWorkFile, err)
	}

	return GoWorkFile, nil
}

func currentModuleVersions() (map[string]string, error) {
	versions := make(map[string]string, len(KnownModules))
	for _, mod := range KnownModules {
		v, err := ReadVersion(PathsFor(mod.Key).VersionFile)
		if err != nil {
			return nil, fmt.Errorf("read version for %s: %w", mod.Label, err)
		}
		versions[mod.Key] = "v" + v
	}

	return versions, nil
}

// replaceRequireVersion replaces the version on the require line for modulePath,
// preserving indentation, the single-line `require` keyword, and any trailing
// comment (e.g. "// indirect"). It handles both single-line and require-block
// forms. Returns the updated contents and whether a replacement was made.
func replaceRequireVersion(goMod, modulePath, version string) (string, bool) {
	lines := strings.Split(goMod, "\n")
	replaced := false
	for i, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))

		// Skip an optional leading "require" keyword (single-line form).
		idx := 0
		if len(fields) > 0 && fields[0] == "require" {
			idx = 1
		}
		if len(fields) < idx+2 || fields[idx] != modulePath {
			continue
		}
		if !strings.HasPrefix(fields[idx+1], "v") {
			continue
		}

		leading := line[:len(line)-len(strings.TrimLeft(line, " \t"))]

		var sb strings.Builder
		sb.WriteString(leading)
		if idx == 1 {
			sb.WriteString("require ")
		}
		sb.WriteString(modulePath)
		sb.WriteString(" ")
		sb.WriteString(version)
		if ci := strings.Index(line, "//"); ci != -1 {
			sb.WriteString(" ")
			sb.WriteString(strings.TrimSpace(line[ci:]))
		}

		lines[i] = sb.String()
		replaced = true
	}
	return strings.Join(lines, "\n"), replaced
}

// replaceWorkspaceReplaceVersion replaces or appends a version-specific go.work
// replace line for modulePath.
func replaceWorkspaceReplaceVersion(goWork, modulePath, version, localPath string) (string, bool) {
	lines := strings.Split(goWork, "\n")
	for i, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 5 || fields[0] != "replace" || fields[1] != modulePath || fields[3] != "=>" {
			continue
		}

		leading := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = leading + "replace " + modulePath + " " + version + " => " + fields[4]
		return strings.Join(lines, "\n"), true
	}

	trimmed := strings.TrimRight(goWork, "\n")
	return trimmed + "\n\nreplace " + modulePath + " " + version + " => " + localPath + "\n", true
}

// DeleteChangeFiles removes the individual changeset .md files.
func DeleteChangeFiles(changes []Change) error {
	for _, ch := range changes {
		if ch.File == "" {
			continue
		}
		if err := os.Remove(ch.File); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// TodayDate returns YYYY-MM-DD in local time.
func TodayDate() string {
	return time.Now().Format("2006-01-02")
}

// BuildReleaseSection generates the markdown block for one release.
func BuildReleaseSection(moduleKey, version, previousVersion, date string, changes []Change) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "## %s — %s\n", version, date)

	byBump := map[string][]Change{BumpPatch: {}, BumpMinor: {}, BumpMajor: {}}
	for _, ch := range changes {
		switch ch.Bump {
		case BumpMajor, BumpMinor, BumpPatch:
			byBump[ch.Bump] = append(byBump[ch.Bump], ch)
		default:
			byBump[BumpPatch] = append(byBump[BumpPatch], ch)
		}
	}

	type sectionInfo struct{ key, heading string }
	order := []sectionInfo{
		{BumpPatch, "Patch Changes"},
		{BumpMinor, "Minor Changes"},
		{BumpMajor, "Major Changes"},
	}
	for _, sec := range order {
		list := byBump[sec.key]
		if len(list) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "### %s\n", sec.heading)
		for _, ch := range list {
			fmt.Fprintf(&sb, "- %s\n", ch.Note)
		}
	}

	sb.WriteString("\n")

	pub := PublishConfigFor(moduleKey)
	prefix := pub.TagPrefix
	// GitHub compare URLs use the repository path only — no Go module major-version
	// suffix (e.g. /v2) even when the module path includes one.
	fmt.Fprintf(&sb, "### [%s%s ... %s%s](https://github.com/tkhq/go-sdk/compare/%s%s...%s%s)\n",
		prefix, previousVersion, prefix, version,
		prefix, previousVersion, prefix, version)

	return sb.String()
}

// MergeChangelog inserts newSection after the "# CHANGELOG" header.
func MergeChangelog(existing, newSection string) string {
	if strings.TrimSpace(existing) == "" {
		return ChangelogHeader + "\n\n" + newSection
	}

	trimmed := strings.TrimSpace(existing)
	if !strings.HasPrefix(trimmed, ChangelogHeader) {
		return ChangelogHeader + "\n\n" + newSection + strings.TrimPrefix("\n"+existing, "\n")
	}

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
		if strings.HasPrefix(rest, "## ") {
			sb.WriteString("\n")
		} else {
			sb.WriteString("\n\n")
		}
		sb.WriteString(rest)
	}

	return sb.String()
}

// BumpModule bumps the VERSION and updates the CHANGELOG for one module.
// It prints a summary line and returns the new version.
func BumpModule(moduleKey string, changes []Change) (string, error) {
	paths := PathsFor(moduleKey)
	bump := MaxBump(changes)

	curVersion, err := ReadVersion(paths.VersionFile)
	if err != nil {
		return "", err
	}

	nextVersion, err := NextVersion(curVersion, bump)
	if err != nil {
		return "", err
	}

	if err := WriteVersion(paths.VersionFile, nextVersion); err != nil {
		return "", err
	}

	section := BuildReleaseSection(moduleKey, nextVersion, curVersion, TodayDate(), changes)

	existing, err := os.ReadFile(paths.ChangelogFile)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read changelog: %w", err)
	}

	newContent := MergeChangelog(string(existing), section)
	if err := os.WriteFile(paths.ChangelogFile, []byte(newContent), fileperms.File); err != nil {
		return "", fmt.Errorf("write changelog: %w", err)
	}

	label := moduleKey
	if label == "" {
		label = "root"
	}
	fmt.Printf("  %s: %s → %s (%s bump)\n", label, curVersion, nextVersion, bump)

	return nextVersion, nil
}
