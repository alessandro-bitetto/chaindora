//go:build !darwin && !linux

package gate

import (
	"fmt"
	"os"
)

func acquireInstallLock(root string) (*os.File, error) {
	return nil, fmt.Errorf("frozen installation and recovery require macOS or Linux")
}
