package changesets

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultDir      = ".changesets"
	ReleaseMetaFile = "current-release.json"
	VersionFile     = "VERSION"
	ChangelogFile   = "CHANGELOG.md"

	BumpMajor = "major"
	BumpMinor = "minor"
	BumpPatch = "patch"
)

type Change struct {
	File  string `json:"file"`
	Title string `json:"title"`
	Bump  string `json:"bump"` // "patch" | "minor" | "major"
	Date  string `json:"date"` // "YYYY-MM-DD"
	Note  string `json:"note"` // full markdown body
}

type ReleaseMeta struct {
	Version         string   `json:"version"`
	PreviousVersion string   `json:"previous_version"`
	Created         string   `json:"created"` // ISO timestamp
	Changes         []Change `json:"changes"`
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

//nolint:gocyclo // parseChangeFile: frontmatter parsing requires sequential validation
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

	return v, nil
}

func WriteVersion(path, version string) error {
	// 0o644 => -rw-r--r-- : owner can read/write, group/others read-only.
	return os.WriteFile(path, []byte(version+"\n"), 0o644)
}

func WriteReleaseMeta(dir string, meta ReleaseMeta) error {
	// 0o755 => drwxr-xr-x : owner can read/write/enter, others can read/enter.
	// Standard for non-sensitive directories so they’re traversable but not writable by others.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	// 0o644 => -rw-r--r-- : owner can read/write, group/others read-only.
	return os.WriteFile(filepath.Join(dir, ReleaseMetaFile), data, 0o644)
}

func ReadReleaseMeta(dir string) (ReleaseMeta, error) {
	data, err := os.ReadFile(filepath.Join(dir, ReleaseMetaFile))
	if err != nil {
		return ReleaseMeta{}, err
	}

	var meta ReleaseMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return ReleaseMeta{}, err
	}

	return meta, nil
}

// DeleteProcessedChanges removes the .md files included in a release and the meta file itself.
func DeleteProcessedChanges(dir string, meta ReleaseMeta) error {
	for _, ch := range meta.Changes {
		if ch.File == "" {
			continue
		}
		if err := os.Remove(ch.File); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	if err := os.Remove(filepath.Join(dir, ReleaseMetaFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}

// TodayDate returns YYYY-MM-DD in local time.
func TodayDate() string {
	return time.Now().Format("2006-01-02")
}
