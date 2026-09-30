//go:build darwin || linux

package gate

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func mustRecovery(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func recoveryTree(t *testing.T, path, value string) {
	t.Helper()
	mustRecovery(t, os.MkdirAll(path, 0700))
	mustRecovery(t, os.WriteFile(filepath.Join(path, "marker"), []byte(value), 0600))
}

// This child exits without defers to emulate process death at durable swap
// boundaries. Fixtures are directories and marker files, never package code.
func TestInstallCrashHelper(t *testing.T) {
	root := os.Getenv("CHAINDORA_CRASH_ROOT")
	if root == "" {
		return
	}
	lock, err := acquireInstallLock(root)
	mustRecovery(t, err)
	defer func() { _ = lock.Close() }() // deliberately bypassed by os.Exit below
	stage, err := os.MkdirTemp(root, ".chaindora-install-")
	mustRecovery(t, err)
	old := os.Getenv("CHAINDORA_CRASH_OLD") == "1"
	if old {
		recoveryTree(t, filepath.Join(root, "node_modules"), "old")
	}
	recoveryTree(t, filepath.Join(stage, "node_modules"), "new")
	journal := installJournal{Version: 1, Stage: filepath.Base(stage), Phase: "staging"}
	mustRecovery(t, saveInstallJournal(root, journal))
	point := os.Getenv("CHAINDORA_CRASH_POINT")
	if point == "staging" {
		os.Exit(0)
	}
	journal.Phase, journal.HadPrevious = "swapping", old
	mustRecovery(t, saveInstallJournal(root, journal))
	if point == "before-swap" {
		os.Exit(0)
	}
	if old {
		mustRecovery(t, os.Rename(filepath.Join(root, "node_modules"), filepath.Join(stage, "previous-node_modules")))
	}
	if point == "after-backup" {
		os.Exit(0)
	}
	mustRecovery(t, os.Rename(filepath.Join(stage, "node_modules"), filepath.Join(root, "node_modules")))
	if point == "after-promotion" {
		os.Exit(0)
	}
	journal.Phase = "committed"
	mustRecovery(t, saveInstallJournal(root, journal))
	if point == "during-cleanup" {
		mustRecovery(t, os.RemoveAll(stage))
	}
	os.Exit(0)
}

func TestInstallRecoversAfterProcessCrash(t *testing.T) {
	for _, old := range []bool{false, true} {
		for _, point := range []string{"staging", "before-swap", "after-backup", "after-promotion", "committed", "during-cleanup"} {
			t.Run(fmt.Sprintf("old=%v/%s", old, point), func(t *testing.T) {
				root := t.TempDir()
				t.Setenv("HOME", t.TempDir())
				t.Setenv("USERPROFILE", os.Getenv("HOME"))
				cmd := exec.Command(os.Args[0], "-test.run=^TestInstallCrashHelper$")
				had := "0"
				if old {
					had = "1"
				}
				cmd.Env = append(os.Environ(), "CHAINDORA_CRASH_ROOT="+root, "CHAINDORA_CRASH_POINT="+point, "CHAINDORA_CRASH_OLD="+had)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("crash helper: %v %s", err, out)
				}
				lock, err := acquireInstallLock(root)
				mustRecovery(t, err)
				defer func() { _ = lock.Close() }()
				mustRecovery(t, recoverNPMInstall(root))
				mustRecovery(t, recoverNPMInstall(root)) // repeat after completed recovery
				data, err := os.ReadFile(filepath.Join(root, "node_modules", "marker"))
				promoted := point == "after-promotion" || point == "committed" || point == "during-cleanup"
				if promoted {
					if err != nil || string(data) != "new" {
						t.Fatalf("committed tree lost: %q %v", data, err)
					}
				} else if old {
					if err != nil || string(data) != "old" {
						t.Fatalf("previous tree lost: %q %v", data, err)
					}
				} else if !os.IsNotExist(err) {
					t.Fatalf("unapproved tree installed: %q %v", data, err)
				}
				if journal, err := readInstallJournal(root); err != nil || journal != nil {
					t.Fatalf("recovery record not cleared: %+v %v", journal, err)
				}
			})
		}
	}
}

func TestPrepareLocksWholeTransactionAndAutomaticallyRecovers(t *testing.T) {
	root, _, client := transactionFixture(t)
	tx, err := PrepareNPMTransaction(context.Background(), "/unused", root, []string{"ci"}, client, t.TempDir())
	mustRecovery(t, err)
	defer func() { _ = tx.Close() }()
	if other, err := PrepareNPMTransaction(context.Background(), "/unused", root, []string{"ci"}, client, t.TempDir()); err == nil {
		_ = other.Close()
		t.Fatal("concurrent transaction acquired project")
	}
	// Simulate the old tree moving aside while the process-held lock is released.
	recoveryTree(t, filepath.Join(tx.Stage, "node_modules"), "new")
	recoveryTree(t, filepath.Join(tx.Stage, "previous-node_modules"), "old")
	mustRecovery(t, saveInstallJournal(root, installJournal{Version: 1, Stage: filepath.Base(tx.Stage), Phase: "swapping", HadPrevious: true}))
	mustRecovery(t, tx.installLock.Close())
	tx.installLock = nil
	next, err := PrepareNPMTransaction(context.Background(), "/unused", root, []string{"ci"}, client, t.TempDir())
	mustRecovery(t, err)
	defer func() {
		if err := next.Close(); err != nil {
			t.Error(err)
		}
	}()
	data, err := os.ReadFile(filepath.Join(root, "node_modules", "marker"))
	if err != nil || string(data) != "old" {
		t.Fatalf("prepare did not recover old tree: %q %v", data, err)
	}
}

func TestInstallInheritedLockHelper(t *testing.T) {
	if os.Getenv("CHAINDORA_LOCK_CHILD") != "1" {
		return
	}
	inherited := os.NewFile(3, "inherited-install-lock")
	defer func() { _ = inherited.Close() }()
	_, _ = fmt.Fprintln(os.Stdout, "ready")
	_, err := bufio.NewReader(os.Stdin).ReadByte()
	mustRecovery(t, err)
}

func TestSurvivingManagerRetainsInstallLock(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	lock, err := acquireInstallLock(root)
	mustRecovery(t, err)
	defer func() { _ = lock.Close() }()
	cmd := exec.Command(os.Args[0], "-test.run=^TestInstallInheritedLockHelper$")
	cmd.Env = append(os.Environ(), "CHAINDORA_LOCK_CHILD=1")
	cmd.ExtraFiles = []*os.File{lock}
	in, err := cmd.StdinPipe()
	mustRecovery(t, err)
	out, err := cmd.StdoutPipe()
	mustRecovery(t, err)
	mustRecovery(t, cmd.Start())
	defer func() { _ = in.Close(); _ = cmd.Process.Kill() }()
	line, err := bufio.NewReader(out).ReadString('\n')
	mustRecovery(t, err)
	if strings.TrimSpace(line) != "ready" {
		t.Fatalf("child not ready: %q", line)
	}
	mustRecovery(t, lock.Close())
	if other, err := acquireInstallLock(root); err == nil {
		_ = other.Close()
		t.Fatal("child lost inherited project lock")
	}
	_, err = in.Write([]byte("x"))
	mustRecovery(t, err)
	mustRecovery(t, cmd.Wait())
	next, err := acquireInstallLock(root)
	mustRecovery(t, err)
	mustRecovery(t, next.Close())
}

func TestRecoveryPreservesAmbiguousOrUntrustedState(t *testing.T) {
	for _, scenario := range []string{"ambiguous", "symlink-stage", "unsafe-journal", "symlink-lock"} {
		t.Run(scenario, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			t.Setenv("HOME", t.TempDir())
			t.Setenv("USERPROFILE", os.Getenv("HOME"))
			recoveryTree(t, outside, "do-not-touch")
			stage := filepath.Join(root, ".chaindora-install-fixture")
			mustRecovery(t, os.Mkdir(stage, 0700))
			journal := installJournal{Version: 1, Stage: filepath.Base(stage), Phase: "swapping", HadPrevious: true}
			switch scenario {
			case "ambiguous":
				recoveryTree(t, filepath.Join(stage, "previous-node_modules"), "old")
			case "symlink-stage":
				mustRecovery(t, os.Remove(stage))
				mustRecovery(t, os.Symlink(outside, stage))
			case "unsafe-journal":
				journal.Stage = "../outside"
			case "symlink-lock":
				mustRecovery(t, os.Symlink(filepath.Join(outside, "marker"), filepath.Join(root, ".chaindora-install.lock")))
			}
			mustRecovery(t, saveInstallJournal(root, journal))
			lock, err := acquireInstallLock(root)
			if scenario == "symlink-lock" {
				if err == nil {
					_ = lock.Close()
					t.Fatal("symlink lock accepted")
				}
			} else {
				mustRecovery(t, err)
				defer func() { _ = lock.Close() }()
				if err := recoverNPMInstall(root); err == nil {
					t.Fatal("unsafe recovery accepted")
				}
			}
			data, err := os.ReadFile(filepath.Join(outside, "marker"))
			if err != nil || string(data) != "do-not-touch" {
				t.Fatal("recovery touched outside data")
			}
			journalPath, err := installJournalPath(root)
			mustRecovery(t, err)
			if _, err := os.Stat(journalPath); err != nil {
				t.Fatal("damaged recovery evidence deleted")
			}
		})
	}
}

func TestProjectCannotSupplyRecoveryAuthority(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	stage := filepath.Join(root, ".chaindora-install-untrusted")
	recoveryTree(t, stage, "keep this repository directory")
	mustRecovery(t, os.WriteFile(filepath.Join(root, ".chaindora-install.json"), []byte(`{"version":1,"stage":".chaindora-install-untrusted","phase":"discard"}`), 0600))
	lock, err := acquireInstallLock(root)
	mustRecovery(t, err)
	defer func() { _ = lock.Close() }()
	mustRecovery(t, recoverNPMInstall(root))
	if _, err := os.Stat(filepath.Join(stage, "marker")); err != nil {
		t.Fatal("project-supplied journal authorized deletion")
	}
}
