package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/tkhq/go-sdk/v2/internal/changesets"
)

type moduleRelease struct {
	label       string
	key         string
	prevVersion string
	nextVersion string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	reader := bufio.NewReader(os.Stdin)

	pending, err := validateState()
	if err != nil {
		return err
	}

	releaseID, err := nextReleaseID(time.Now())
	if err != nil {
		return fmt.Errorf("compute release id: %w", err)
	}
	branchName := "release/" + releaseID

	if _, err := gitOutput("rev-parse", "--verify", branchName); err == nil {
		return fmt.Errorf("branch %q already exists — delete it and rerun", branchName)
	}

	if err := gitRun("checkout", "-b", branchName); err != nil {
		return fmt.Errorf("create branch: %w", err)
	}

	releases, err := bumpModules(changesets.GroupByModule(pending))
	if err != nil {
		return err
	}

	changedFiles, err := updateReleaseModuleGraph()
	if err != nil {
		return err
	}

	if err := commitRelease(releaseID, releases, pending, changedFiles); err != nil {
		return err
	}

	printReleaseSummary(branchName, releases, changedFiles)

	return pushAndOpenPR(reader, branchName, releaseID, releases)
}

func updateReleaseModuleGraph() ([]string, error) {
	// Point every inter-module require at the just-bumped versions so the
	// published module graph is consistent (local dev still resolves via go.work).
	goMods, err := changesets.UpdateModuleRequires()
	if err != nil {
		return nil, fmt.Errorf("update go.mod requires: %w", err)
	}

	goWork, err := changesets.UpdateWorkspaceReplaces()
	if err != nil {
		return nil, fmt.Errorf("update go.work replaces: %w", err)
	}

	return appendChangedFiles(goMods, goWork), nil
}

func printReleaseSummary(branchName string, releases []moduleRelease, changedFiles []string) {
	fmt.Printf("\n✅ Branch %q created:\n", branchName)
	for _, r := range releases {
		pub := changesets.PublishConfigFor(r.key)
		fmt.Printf("   %s%s → %s%s\n", pub.TagPrefix, r.prevVersion, pub.TagPrefix, r.nextVersion)
	}
	for _, f := range changedFiles {
		fmt.Printf("   updated %s\n", f)
	}
}

// nextReleaseID returns the next release identifier (vYYYY-MM-N) for the
// current month, scanning local and remote release/* branches to pick N.
func nextReleaseID(now time.Time) (string, error) {
	prefix := fmt.Sprintf("v%04d-%02d-", now.Year(), int(now.Month()))

	out, err := gitOutput(
		"for-each-ref",
		"--format=%(refname:short)",
		"refs/heads/release/"+prefix+"*",
		"refs/remotes/origin/release/"+prefix+"*",
	)
	if err != nil {
		return "", fmt.Errorf("list release branches: %w", err)
	}

	maxN := 0
	for line := range strings.SplitSeq(out, "\n") {
		ref := strings.TrimSpace(line)
		if ref == "" {
			continue
		}
		ref = strings.TrimPrefix(ref, "origin/")
		ref = strings.TrimPrefix(ref, "release/")
		if !strings.HasPrefix(ref, prefix) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(ref, prefix))
		if err != nil {
			continue
		}
		if n > maxN {
			maxN = n
		}
	}

	return fmt.Sprintf("%s%d", prefix, maxN+1), nil
}

func validateState() ([]changesets.Change, error) {
	branch, err := gitOutput("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("get branch: %w", err)
	}
	if branch != "main" {
		return nil, fmt.Errorf("must be on main branch (currently on %q)", branch)
	}

	status, err := gitOutput("status", "--porcelain")
	if err != nil {
		return nil, fmt.Errorf("git status: %w", err)
	}
	if status != "" {
		return nil, fmt.Errorf("working tree is dirty — commit or stash changes first")
	}

	pending, err := changesets.LoadPending(changesets.DefaultDir)
	if err != nil {
		return nil, err
	}
	if len(pending) == 0 {
		return nil, fmt.Errorf("no pending changesets — run `make changeset` first")
	}
	return pending, nil
}

func bumpModules(byModule map[string][]changesets.Change) ([]moduleRelease, error) {
	var releases []moduleRelease
	for _, mod := range changesets.KnownModules {
		changes, ok := byModule[mod.Key]
		if !ok {
			continue
		}

		paths := changesets.PathsFor(mod.Key)
		prevVersion, err := changesets.ReadVersion(paths.VersionFile)
		if err != nil {
			return nil, err
		}

		nextVersion, err := changesets.BumpModule(mod.Key, changes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", mod.Label, err)
		}

		releases = append(releases, moduleRelease{
			label:       mod.Label,
			key:         mod.Key,
			prevVersion: prevVersion,
			nextVersion: nextVersion,
		})
	}
	return releases, nil
}

func commitRelease(date string, releases []moduleRelease, pending []changesets.Change, goMods []string) error {
	if err := changesets.DeleteChangeFiles(pending); err != nil {
		return fmt.Errorf("cleanup changesets: %w", err)
	}

	stagedFiles := collectStagedFiles(releases)
	stagedFiles = append(stagedFiles, goMods...)
	stagedFiles = append(stagedFiles, changesets.DefaultDir)
	if err := gitRun(append([]string{"add"}, stagedFiles...)...); err != nil {
		return fmt.Errorf("git add: %w", err)
	}

	if err := gitRun("commit", "-m", buildCommitMessage(date, releases)); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	return nil
}

func pushAndOpenPR(reader *bufio.Reader, branchName, date string, releases []moduleRelease) error {
	answer, err := promptLine(reader, "\nPush and open PR? (y/N): ")
	if err != nil {
		return err
	}
	if strings.ToLower(answer) != "y" {
		fmt.Printf("\nWhen ready:\n  git push -u origin %s\n", branchName)
		return nil
	}

	if err := gitRun("push", "-u", "origin", branchName); err != nil {
		return fmt.Errorf("git push: %w", err)
	}

	if err := ghRun(
		"pr", "create",
		"--title", "chore: release "+date,
		"--body", buildPRBody(date, releases),
		"--base", "main",
	); err != nil {
		return fmt.Errorf("gh pr create: %w", err)
	}
	return nil
}

func appendChangedFiles(files []string, extra string) []string {
	if extra == "" {
		return files
	}
	return append(files, extra)
}

// collectStagedFiles returns the VERSION and CHANGELOG paths for every bumped module.
func collectStagedFiles(releases []moduleRelease) []string {
	files := make([]string, 0, 2*len(releases))
	for _, r := range releases {
		paths := changesets.PathsFor(r.key)
		files = append(files, paths.VersionFile, paths.ChangelogFile)
	}
	return files
}

func buildCommitMessage(date string, releases []moduleRelease) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "chore: release %s\n\n", date)
	for _, r := range releases {
		pub := changesets.PublishConfigFor(r.key)
		fmt.Fprintf(&sb, "- %s%s\n", pub.TagPrefix, r.nextVersion)
	}
	return sb.String()
}

func buildPRBody(date string, releases []moduleRelease) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Release %s\n\n", date)
	for _, r := range releases {
		pub := changesets.PublishConfigFor(r.key)
		fmt.Fprintf(
			&sb, "- **%s**: `%s%s` → `%s%s`\n",
			r.label,
			pub.TagPrefix, r.prevVersion,
			pub.TagPrefix, r.nextVersion,
		)
	}
	sb.WriteString("\n_Merging this PR will trigger CI to tag and publish each module above._")
	return sb.String()
}

func gitRun(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func gitOutput(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func ghRun(args ...string) error {
	cmd := exec.Command("gh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func promptLine(r *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
