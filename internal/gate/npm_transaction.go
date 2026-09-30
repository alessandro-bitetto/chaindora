package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/artifacts"
)

type NPMLockedPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Link      bool   `json:"link"`
	Optional  bool   `json:"optional"`
}

// NPMLockPackages validates install paths before callers read or replace files.
// Workspace links, bundles without independent hashes and old lock formats are
// explicitly unsupported in the frozen transaction path.
func NPMLockPackages(data []byte) (map[string]NPMLockedPackage, error) {
	var lock struct {
		LockfileVersion int                         `json:"lockfileVersion"`
		Packages        map[string]NPMLockedPackage `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	if lock.LockfileVersion != 2 && lock.LockfileVersion != 3 {
		return nil, fmt.Errorf("verified npm installs require a v2 or v3 package-lock.json")
	}
	delete(lock.Packages, "")
	if len(lock.Packages) == 0 {
		return nil, fmt.Errorf("lockfile has no inspectable packages")
	}
	for key, pkg := range lock.Packages {
		if !validNPMInstallPath(key) || pkg.Link {
			return nil, fmt.Errorf("unsupported npm install path %q", key)
		}
		if pkg.Name == "" {
			pkg.Name = stripNodeModulesPath(key)
		}
		if pkg.Version == "" || pkg.Integrity == "" {
			return nil, fmt.Errorf("%s is missing resolved version or integrity", key)
		}
		if err := artifacts.NPMURL(pkg.Resolved); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		lock.Packages[key] = pkg
	}
	return lock.Packages, nil
}

func validNPMInstallPath(key string) bool {
	if !artifacts.SafePath(key) {
		return false
	}
	parts := strings.Split(key, "/")
	for len(parts) > 0 {
		if len(parts) < 2 || parts[0] != "node_modules" || parts[1] == ".bin" {
			return false
		}
		parts = parts[1:]
		if strings.HasPrefix(parts[0], "@") {
			if len(parts) < 2 {
				return false
			}
			parts = parts[2:]
		} else {
			parts = parts[1:]
		}
	}
	return true
}

// NPMTransaction restores a frozen lock in a private staging directory, using
// only artifacts already checked. No resolver or original install command is
// executed. The caller must evaluate Refs before calling Install.
type NPMTransaction struct {
	Root, Stage, NPM               string
	Refs                           []PackageRef
	Packages                       map[string]NPMLockedPackage
	manifests                      map[string]*artifacts.Manifest
	originalManifest, originalLock []byte
	installLock                    *os.File
}

func PrepareNPMTransaction(ctx context.Context, npm, root string, args []string, client *http.Client, cacheRoot string) (_ *NPMTransaction, err error) {
	if err := ValidateNPMRestoreArgs(args); err != nil {
		return nil, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	installLock, err := acquireInstallLock(root)
	if err != nil {
		return nil, err
	}
	tx := &NPMTransaction{Root: root, NPM: npm, installLock: installLock}
	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Close())
		}
	}()
	if err := recoverNPMInstall(root); err != nil {
		return nil, fmt.Errorf("install recovery: %w", err)
	}
	manifest, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("frozen install requires package.json: %w", err)
	}
	lock, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if err != nil {
		return nil, fmt.Errorf("frozen install requires an existing package-lock.json; create and review the lockfile separately: %w", err)
	}
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(manifest, &pkg); err != nil {
		return nil, err
	}
	if _, ok := pkg["workspaces"]; ok {
		return nil, fmt.Errorf("workspace installs require a dedicated frozen adapter and are refused")
	}
	for _, name := range []string{"npm-shrinkwrap.json", ".npmrc"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			return nil, fmt.Errorf("%s is unsupported by the frozen npm adapter", name)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	packages, err := NPMLockPackages(lock)
	if err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(root, ".chaindora-install-*")
	if err != nil {
		return nil, err
	}
	tx.Stage, tx.Packages, tx.manifests = stage, packages, map[string]*artifacts.Manifest{}
	tx.originalManifest, tx.originalLock = manifest, lock
	if err := saveInstallJournal(root, installJournal{Version: 1, Stage: filepath.Base(stage), Phase: "staging"}); err != nil {
		// The newly created empty stage has never held an old installation.
		_ = os.RemoveAll(stage)
		return nil, err
	}
	for name, data := range map[string][]byte{"package.json": manifest, "package-lock.json": lock, "user.npmrc": {}, "global.npmrc": {}} {
		if err := os.WriteFile(filepath.Join(stage, name), data, 0o600); err != nil {
			return nil, err
		}
	}
	keys := make([]string, 0, len(packages))
	for key := range packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	direct := map[string]bool{}
	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		var declared map[string]json.RawMessage
		if raw, ok := pkg[field]; ok {
			if err := json.Unmarshal(raw, &declared); err != nil {
				return nil, fmt.Errorf("invalid %s: %w", field, err)
			}
		}
		for name := range declared {
			if entry, ok := packages["node_modules/"+name]; ok {
				direct[entry.Name+"@"+entry.Version] = true
			}
		}
	}
	seen := map[string]PackageRef{}
	var total int
	for _, key := range keys {
		entry := packages[key]
		id := entry.Name + "@" + entry.Version
		if prev, ok := seen[id]; ok {
			if prev.Integrity != entry.Integrity {
				return nil, fmt.Errorf("conflicting artifact identity for %s", id)
			}
			tx.manifests[key] = tx.manifests["artifact:"+id]
			continue
		}
		data, err := artifacts.LoadNPM(ctx, client, cacheRoot, entry.Resolved, entry.Integrity, false)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		total += len(data)
		if total > 512<<20 {
			return nil, fmt.Errorf("transaction artifacts exceed 512 MiB")
		}
		m, err := artifacts.NPMManifest(data, entry.Integrity)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		if m.Name != entry.Name || m.Version != entry.Version {
			return nil, fmt.Errorf("artifact identity does not match lockfile for %s", id)
		}
		for name := range m.Files {
			if strings.HasPrefix(name, "node_modules/") {
				return nil, fmt.Errorf("bundled dependencies in %s require a dedicated frozen adapter", id)
			}
		}
		file := filepath.Join(stage, fmt.Sprintf("artifact-%d.tgz", len(tx.Refs)))
		if err := os.WriteFile(file, data, 0o600); err != nil {
			return nil, err
		}
		ref := PackageRef{Ecosystem: "npm", Name: entry.Name, Version: entry.Version, Integrity: entry.Integrity, ArtifactPath: file, Direct: direct[id]}
		seen[id] = ref
		tx.Refs = append(tx.Refs, ref)
		tx.manifests[key] = m
		tx.manifests["artifact:"+id] = m
	}
	return tx, nil
}

func ValidateNPMRestoreArgs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("specify npm ci or npm install with an existing lockfile")
	}
	switch args[0] {
	case "ci", "clean-install", "ic", "install-clean", "isntall-clean", "install", "i", "add", "in", "ins", "isnt", "isntall":
	default:
		return fmt.Errorf("npm %s is not a supported frozen install; use npm ci with a reviewed lockfile", args[0])
	}
	for _, arg := range args[1:] {
		switch arg {
		case "--ignore-scripts", "--no-audit", "--no-fund":
		default:
			return fmt.Errorf("argument %q requires fresh resolution or unsupported install settings; only frozen npm restores are supported", arg)
		}
	}
	return nil
}

// npmEnvironment deliberately omits NODE_OPTIONS, package-manager overrides,
// credentials, and user config. The installed npm/node executables are trusted.
func npmEnvironment(stage string) []string {
	env := []string{}
	for _, key := range []string{"PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return append(env, "HOME="+stage, "USERPROFILE="+stage, "TMPDIR="+stage, "TMP="+stage, "TEMP="+stage)
}

func (tx *NPMTransaction) run(ctx context.Context, args ...string) error {
	args = append(args, "--ignore-scripts", "--no-audit", "--no-fund", "--offline", "--workspaces=false",
		"--cache="+filepath.Join(tx.Stage, "cache"), "--userconfig="+filepath.Join(tx.Stage, "user.npmrc"),
		"--globalconfig="+filepath.Join(tx.Stage, "global.npmrc"), "--registry=https://registry.npmjs.org")
	cmd := exec.CommandContext(ctx, tx.NPM, args...)
	cmd.Dir = tx.Stage
	cmd.Env = npmEnvironment(tx.Stage)
	// A surviving npm child retains the lock if the CLI is killed. Go closes
	// this descriptor on exec unless explicitly passed here.
	if tx.installLock != nil {
		cmd.ExtraFiles = []*os.File{tx.installLock}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return wrapPMError("npm", "frozen install", out, err)
	}
	return nil
}

func (tx *NPMTransaction) Install(ctx context.Context) error {
	if tx.installLock == nil {
		return fmt.Errorf("install transaction is closed or unlocked")
	}
	if err := tx.unchanged(); err != nil {
		return err
	}
	for _, ref := range tx.Refs {
		data, err := os.ReadFile(ref.ArtifactPath)
		if err != nil {
			return err
		}
		if err := artifacts.VerifyIntegrity(data, ref.Integrity); err != nil {
			return err
		}
		if err := tx.run(ctx, "cache", "add", ref.ArtifactPath); err != nil {
			return err
		}
	}
	if err := tx.run(ctx, "ci"); err != nil {
		return err
	}
	installedLock, err := os.ReadFile(filepath.Join(tx.Stage, "node_modules", ".package-lock.json"))
	if err != nil {
		return fmt.Errorf("missing installed graph evidence: %w", err)
	}
	installedGraph, err := NPMLockPackages(installedLock)
	if err != nil {
		return fmt.Errorf("invalid installed graph evidence: %w", err)
	}
	for key, got := range installedGraph {
		want, ok := tx.Packages[key]
		if !ok || got.Name != want.Name || got.Version != want.Version || got.Integrity != want.Integrity || got.Resolved != want.Resolved {
			return fmt.Errorf("installed graph differs from approved lock at %s", key)
		}
	}
	for key, entry := range tx.Packages {
		root := filepath.Join(tx.Stage, filepath.FromSlash(key))
		if _, err := os.Lstat(root); os.IsNotExist(err) && entry.Optional {
			continue
		}
		if err := artifacts.DirectoryPath(tx.Stage, key); err != nil {
			return err
		}
		diffs, err := artifacts.CompareFiles(root, tx.manifests[key])
		if err != nil {
			return fmt.Errorf("verify installed %s: %w", key, err)
		}
		if len(diffs) > 0 {
			return fmt.Errorf("installed artifact mismatch: %s (%s)", diffs[0].Path, diffs[0].Reason)
		}
	}
	for name, want := range map[string][]byte{"package.json": tx.originalManifest, "package-lock.json": tx.originalLock} {
		got, err := os.ReadFile(filepath.Join(tx.Stage, name))
		if err != nil || !bytes.Equal(got, want) {
			return fmt.Errorf("npm changed frozen %s", name)
		}
	}
	if err := tx.unchanged(); err != nil {
		return err
	}
	if err := tx.commitInstall(); err != nil {
		return errors.Join(err, recoverNPMInstall(tx.Root))
	}
	return nil
}

func (tx *NPMTransaction) unchanged() error {
	for name, want := range map[string][]byte{"package.json": tx.originalManifest, "package-lock.json": tx.originalLock} {
		got, err := os.ReadFile(filepath.Join(tx.Root, name))
		if err != nil || !bytes.Equal(got, want) {
			return fmt.Errorf("%s changed after approval; refusing installation", name)
		}
	}
	return nil
}

// Close recovers/cleans only while holding the project lock. A cleanup failure
// leaves the journal and backup for the next invocation, never blindly deleting it.
func (tx *NPMTransaction) Close() error {
	if tx.installLock == nil {
		return nil
	}
	err := recoverNPMInstall(tx.Root)
	closeErr := tx.installLock.Close()
	tx.installLock = nil
	return errors.Join(err, closeErr)
}
