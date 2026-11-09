//go:build unix

package relay

import (
	"os"
	"syscall"
)

// 整个文件的排他锁，拿不到就等（store.go locked）。Windows 没有 flock，见 lock_windows.go。
func lockFile(f *os.File) error   { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }
func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
