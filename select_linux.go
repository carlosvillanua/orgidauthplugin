//go:build linux

package orgidauthplugin

import (
	"fmt"
	"syscall"
	"time"
)

func selectWithTimeout(fd int, fdSet *syscall.FdSet, timeout time.Duration) error {
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	n, err := syscall.Select(fd+1, nil, fdSet, nil, &tv)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("connection timeout")
	}
	return nil
}
