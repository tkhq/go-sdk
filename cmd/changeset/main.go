package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tkhq/go-sdk/v2/internal/changesets"
	"github.com/tkhq/go-sdk/v2/internal/fileperms"
)

var bumpOptions = []string{"patch", "minor", "major"}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== Create Go Changeset ===")

	// 1) Pick module
	module, err := promptModule(reader)
	if err != nil {
		return err
	}

	// All changesets live in the root .changesets/ dir, tagged with their module.
	changesetDir := changesets.DefaultDir

	// 2) Pick bump type
	bump, err := promptBump(reader)
	if err != nil {
		return err
	}

	// 3) Title
	title, err := promptLine(reader, "Short title for this change: ")
	if err != nil {
		return err
	}

	if title == "" {
		return errors.New("title cannot be empty")
	}

	// 4) Note / description
	note, err := promptMultiline(
		reader,
		"Enter a longer description (markdown allowed).\n"+
			"End input with a single '.' on its own line.\n\n",
	)
	if err != nil {
		return err
	}

	// 5) Build filename + contents
	now := time.Now()
	slug := slugify(title)
	filename := fmt.Sprintf("%s-%s.md", now.Format("20060102-150405"), slug)
	path := filepath.Join(changesetDir, filename)

	if err := os.MkdirAll(changesetDir, fileperms.Dir); err != nil {
		return fmt.Errorf("creating %s: %w", changesetDir, err)
	}

	content := buildMarkdownFile(module, title, bump, now, note)

	if err := os.WriteFile(path, []byte(content), fileperms.File); err != nil {
		return fmt.Errorf("writing changeset file: %w", err)
	}

	fmt.Printf("\n✅ Changeset written to %s\n", path)

	return nil
}

func promptModule(r *bufio.Reader) (string, error) {
	fmt.Println("Select module:")

	for i, m := range changesets.KnownModules {
		fmt.Printf("  %d) %s\n", i+1, m.Label)
	}

	n := len(changesets.KnownModules)
	for {
		answer, err := promptLine(r, fmt.Sprintf("Choice (1-%d): ", n))
		if err != nil {
			return "", err
		}

		if len(answer) == 1 {
			idx := int(answer[0] - '1')
			if idx >= 0 && idx < n {
				return changesets.KnownModules[idx].Key, nil
			}
		}

		fmt.Printf("Invalid choice, please enter 1-%d.\n", n)
	}
}

func promptBump(r *bufio.Reader) (string, error) {
	fmt.Println("Select bump type:")

	for i, opt := range bumpOptions {
		fmt.Printf("  %d) %s\n", i+1, opt)
	}

	for {
		answer, err := promptLine(r, "Choice (1-3): ")
		if err != nil {
			return "", err
		}

		switch answer {
		case "1", "2", "3":
			idx := int(answer[0] - '1')
			return bumpOptions[idx], nil
		default:
			fmt.Println("Invalid choice, please enter 1, 2, or 3.")
		}
	}
}

func promptLine(r *bufio.Reader, label string) (string, error) {
	fmt.Print(label)

	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	return strings.TrimSpace(line), nil
}

func promptMultiline(r *bufio.Reader, intro string) (string, error) {
	fmt.Print(intro)

	var lines []string

	for {
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}

		line = strings.TrimRight(line, "\r\n")

		if line == "." {
			break
		}

		lines = append(lines, line)

		if errors.Is(err, io.EOF) {
			break
		}
	}

	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	return strings.Join(lines, "\n"), nil
}

func buildMarkdownFile(module, title, bump string, t time.Time, note string) string {
	var sb strings.Builder

	moduleVal := module
	if moduleVal == "" {
		moduleVal = "root"
	}

	sb.WriteString("---\n")
	fmt.Fprintf(&sb, "module: %q\n", moduleVal)
	fmt.Fprintf(&sb, "bump: %q\n", bump)
	fmt.Fprintf(&sb, "title: %q\n", title)
	fmt.Fprintf(&sb, "date: %q\n", t.Format("2006-01-02"))
	sb.WriteString("---\n\n")

	if strings.TrimSpace(note) != "" {
		sb.WriteString(note)
	}

	sb.WriteString("\n")

	return sb.String()
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))

	var b strings.Builder

	prevDash := false

	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)

			prevDash = false

			continue
		}

		if strings.ContainsRune(" -_", r) {
			if !prevDash {
				b.WriteRune('-')

				prevDash = true
			}

			continue
		}
	}

	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "changeset"
	}

	return slug
}
