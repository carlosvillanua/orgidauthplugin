//go:build darwin

package orgidauthplugin

import (
	"syscall"
	"time"
)

func selectWithTimeout(fd int, fdSet *syscall.FdSet, timeout time.Duration) error {
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	return syscall.Select(fd+1, nil, fdSet, nil, &tv)
}
