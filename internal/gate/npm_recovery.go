package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Recovery authority lives outside the project: repository-controlled files
// must not be able to authorize moves/deletions of installation directories.
func installJournalPath(root string) (string, error) {
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(canonical))
	return filepath.Join(home, ".chaindora", "install-transactions", fmt.Sprintf("%x.json", key)), nil
}

type installJournal struct {
	Version     int    `json:"version"`
	Stage       string `json:"stage"`
	Phase       string `json:"phase"`
	HadPrevious bool   `json:"had_previous"`
}

func syncInstallDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

func saveInstallJournal(root string, journal installJournal) error {
	journalPath, err := installJournalPath(root)
	if err != nil {
		return err
	}
	journalDir := filepath.Dir(journalPath)
	if err := os.MkdirAll(journalDir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(journalDir, ".journal-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(file.Name(), journalPath); err != nil {
		return err
	}
	return syncInstallDir(journalDir)
}

func readInstallJournal(root string) (*installJournal, error) {
	path, err := installJournalPath(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return nil, fmt.Errorf("invalid install recovery journal %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var journal installJournal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("invalid trailing recovery journal data")
	}
	if journal.Version != 1 || !strings.HasPrefix(journal.Stage, ".chaindora-install-") || len(journal.Stage) == len(".chaindora-install-") || filepath.Base(journal.Stage) != journal.Stage || strings.ContainsAny(journal.Stage, "/\\:") {
		return nil, fmt.Errorf("unsafe install recovery journal")
	}
	switch journal.Phase {
	case "staging", "swapping", "discard", "committed":
	default:
		return nil, fmt.Errorf("unknown install recovery phase %q", journal.Phase)
	}
	return &journal, nil
}

// directoryPresent never follows symlinks, including at the staging boundary.
func directoryPresent(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("recovery requires a directory, not a symlink or file: %s", path)
	}
	return true, nil
}

// recoverNPMInstall requires the project lock. Its transitions are restartable:
// a second interruption leaves either the same state or another recoverable one.
// Ambiguous/damaged states preserve all data for review instead of guessing.
func recoverNPMInstall(root string) error {
	journal, err := readInstallJournal(root)
	if err != nil || journal == nil {
		return err
	}
	stage := filepath.Join(root, journal.Stage)
	stagePresent, err := directoryPresent(stage)
	if err != nil {
		return err
	}
	if !stagePresent && journal.Phase == "swapping" {
		return fmt.Errorf("interrupted install stage is missing; refusing ambiguous recovery")
	}
	target := filepath.Join(root, "node_modules")
	backup := filepath.Join(stage, "previous-node_modules")
	next := filepath.Join(stage, "node_modules")
	old, err := directoryPresent(backup)
	if err != nil {
		return err
	}
	switch journal.Phase {
	case "staging", "discard":
		if old {
			return fmt.Errorf("unexpected previous installation at %s; recovery preserved it", backup)
		}
		// Persist the cleanup phase before deleting any staged evidence.
		journal.Phase = "discard"
	case "swapping":
		current, err := directoryPresent(target)
		if err != nil {
			return err
		}
		staged, err := directoryPresent(next)
		if err != nil {
			return err
		}
		switch {
		case current && !staged && old == journal.HadPrevious:
			// The verified replacement is already visible; complete its commit.
			journal.Phase = "committed"
		case staged && !current && old && journal.HadPrevious:
			if err := os.Rename(backup, target); err != nil {
				return err
			}
			if err := syncInstallDir(root); err != nil {
				return err
			}
			if err := syncInstallDir(stage); err != nil {
				return err
			}
			journal.Phase = "discard"
		case staged && !old && current == journal.HadPrevious:
			// Nothing was replaced, or the previous tree was just restored.
			journal.Phase = "discard"
		default:
			return fmt.Errorf("ambiguous interrupted install at %s; previous/staged data preserved", stage)
		}
	case "committed":
		present, err := directoryPresent(target)
		if err != nil {
			return err
		}
		if !present {
			return fmt.Errorf("committed install is missing; backup preserved at %s", backup)
		}
	}
	if err := saveInstallJournal(root, *journal); err != nil {
		return err
	}
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	// Stage/backup cleanup must reach disk before removing the recovery record.
	if err := syncInstallDir(root); err != nil {
		return err
	}
	journalPath, err := installJournalPath(root)
	if err != nil {
		return err
	}
	if err := os.Remove(journalPath); err != nil {
		return err
	}
	return syncInstallDir(filepath.Dir(journalPath))
}

func (tx *NPMTransaction) commitInstall() error {
	target := filepath.Join(tx.Root, "node_modules")
	hadPrevious, err := directoryPresent(target)
	if err != nil {
		return err
	}
	journal := installJournal{Version: 1, Stage: filepath.Base(tx.Stage), Phase: "swapping", HadPrevious: hadPrevious}
	// All policy, graph and file checks completed before the write-ahead record.
	if err := saveInstallJournal(tx.Root, journal); err != nil {
		return err
	}
	if hadPrevious {
		if err := os.Rename(target, filepath.Join(tx.Stage, "previous-node_modules")); err != nil {
			return err
		}
		if err := syncInstallDir(tx.Root); err != nil {
			return err
		}
		if err := syncInstallDir(tx.Stage); err != nil {
			return err
		}
	}
	if err := os.Rename(filepath.Join(tx.Stage, "node_modules"), target); err != nil {
		return err
	}
	if err := syncInstallDir(tx.Root); err != nil {
		return err
	}
	if err := syncInstallDir(tx.Stage); err != nil {
		return err
	}
	journal.Phase = "committed"
	return saveInstallJournal(tx.Root, journal)
}
