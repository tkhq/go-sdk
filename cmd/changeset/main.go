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
)

const changesetDir = ".changesets"

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

	// 1) Pick bump type
	bump, err := promptBump(reader)
	if err != nil {
		return err
	}

	// 2) Title
	title, err := promptLine(reader, "Short title for this change: ")
	if err != nil {
		return err
	}

	if title == "" {
		return errors.New("title cannot be empty")
	}

	// 3) Note / description
	note, err := promptMultiline(reader,
		"Enter a longer description (markdown allowed).\n"+
			"End input with a single '.' on its own line.\n\n",
	)
	if err != nil {
		return err
	}

	// 4) Build filename + contents
	now := time.Now()
	slug := slugify(title)
	filename := fmt.Sprintf("%s-%s.md", now.Format("20060102-150405"), slug)
	path := filepath.Join(changesetDir, filename)

	if err := os.MkdirAll(changesetDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", changesetDir, err)
	}

	content := buildMarkdownFile(title, bump, now, note)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing changeset file: %w", err)
	}

	fmt.Printf("\n✅ Changeset written to %s\n", path)

	return nil
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

	line = strings.TrimSpace(line)

	return line, nil
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

		// Stop condition
		if line == "." {
			break
		}

		lines = append(lines, line)

		if errors.Is(err, io.EOF) {
			break
		}
	}

	// Trim trailing empty lines for neatness
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	return strings.Join(lines, "\n"), nil
}

func buildMarkdownFile(title, bump string, t time.Time, note string) string {
	var sb strings.Builder

	sb.WriteString("---\n")
	sb.WriteString(fmt.Sprintf("title: %q\n", title))
	sb.WriteString(fmt.Sprintf("bump: %q\n", bump))
	sb.WriteString(fmt.Sprintf("date: %q\n", t.Format("2006-01-02")))
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
		// ignore everything else
	}

	slug := strings.Trim(b.String(), "-")

	if slug == "" {
		slug = "changeset"
	}

	return slug
}
