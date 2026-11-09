//go:build windows

package relay

import (
	"os"

	"golang.org/x/sys/windows"
)

// Windows 上和 flock(LOCK_EX) 对应的：LockFileEx 锁住整个文件，排他，拿不到就等。
// 没有这个文件的话 relay 在 Windows 上编不过（gerdr 的 Windows 版 import 了它的主机那一半）。
func lockFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped))
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
