//go:build windows

package fsx

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx                 = kernel32.NewProc("LockFileEx")
	procUnlockFileEx               = kernel32.NewProc("UnlockFileEx")
	procMoveFileExW                = kernel32.NewProc("MoveFileExW")
	procSetFileInformationByHandle = kernel32.NewProc("SetFileInformationByHandle")
)

// Windows constants that package syscall does not define.
const (
	fileWriteEA             = 0x0010   // FILE_WRITE_EA
	accessDelete            = 0x10000  // DELETE
	standardRightsWrite     = 0x20000  // STANDARD_RIGHTS_WRITE (READ_CONTROL)
	synchronize             = 0x100000 // SYNCHRONIZE
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	movefileReplaceExisting = 0x1
	movefileWriteThrough    = 0x8

	fileRenameInfoEx                        = 22  // FILE_INFO_BY_HANDLE_CLASS FileRenameInfoEx
	fileRenameReplaceIfExists               = 0x1 // FILE_RENAME_FLAG_REPLACE_IF_EXISTS
	fileRenamePosixSemantics                = 0x2 // FILE_RENAME_FLAG_POSIX_SEMANTICS
	errorInvalidFunction      syscall.Errno = 1
	errorSharingViolation     syscall.Errno = 32
	errorLockViolation        syscall.Errno = 33
	errorNotSupported         syscall.Errno = 50
	errorInvalidParameter     syscall.Errno = 87

	// shareAll lets other handles read, write, rename, and delete the file,
	// as Unix always does. Without FILE_SHARE_DELETE an open reader would
	// make replacing or rotating the file fail.
	shareAll = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE
)

// createFile opens path with CreateFile: sharing all access (see shareAll)
// and not inherited by programs NetShift starts.
func createFile(path string, access, disposition, flags uint32) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(name, access, shareAll, nil, disposition, syscall.FILE_ATTRIBUTE_NORMAL|flags, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// openRead opens path for reading. It follows links, as os.Open does.
func openRead(path string) (*os.File, error) {
	return createFile(path, syscall.GENERIC_READ, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS)
}

// openNoFollow opens path with flag for OpenRegular, creating it if absent.
// FILE_FLAG_OPEN_REPARSE_POINT opens a symlink, junction, or other reparse
// point itself rather than its target, and the handle's attributes then
// refuse it, so a link cannot be swapped in between a check and the open.
// Devices such as NUL or a named pipe are refused too.
//
// O_WRONLY|O_APPEND grants append-only access, so every write lands at the
// end of the file even with several writers, as the event log needs; read
// access comes with it, which LockFileEx needs. O_RDWR|O_APPEND, which the
// single writer of the history file uses, needs write access to truncate a
// partial record; it gets it, and the handle starts at the end of the file.
func openNoFollow(path string, flag int) (*os.File, error) {
	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = syscall.GENERIC_READ
	case os.O_WRONLY:
		access = syscall.GENERIC_WRITE
	case os.O_RDWR:
		access = syscall.GENERIC_READ | syscall.GENERIC_WRITE
	}
	appendOnly := flag&os.O_APPEND != 0 && flag&os.O_RDWR == 0
	if appendOnly {
		access &^= syscall.GENERIC_WRITE
		access |= syscall.GENERIC_READ | syscall.FILE_APPEND_DATA | syscall.FILE_WRITE_ATTRIBUTES | fileWriteEA | standardRightsWrite | synchronize
	}
	// Backup semantics lets a directory open too, so that it is refused as
	// one below rather than with "Access is denied".
	f, err := createFile(path, access, syscall.OPEN_ALWAYS, syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS)
	if err != nil {
		if info, lerr := os.Lstat(path); errors.Is(err, syscall.ERROR_ACCESS_DENIED) && lerr == nil && !info.Mode().IsRegular() {
			return nil, errNotRegular
		}
		return nil, err
	}
	h := syscall.Handle(f.Fd())
	// Devices have no file information, so check the type first.
	switch kind, typeErr := syscall.GetFileType(h); {
	case typeErr != nil:
		err = typeErr
	case kind != syscall.FILE_TYPE_DISK:
		err = errNotRegular
	default:
		var info syscall.ByHandleFileInformation
		err = syscall.GetFileInformationByHandle(h, &info)
		if err == nil && info.FileAttributes&(syscall.FILE_ATTRIBUTE_REPARSE_POINT|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 {
			err = errNotRegular
		}
	}
	if err == nil && flag&os.O_APPEND != 0 && !appendOnly {
		_, err = f.Seek(0, io.SeekEnd)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// isLink reports whether info, from Lstat, describes a symlink, junction, or
// other reparse point.
func isLink(info fs.FileInfo) bool {
	if info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return true
	}
	a, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && a.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// replaceFile moves temp over name in dir (see Rename). It works by path,
// not through root, but temp has a random name that only this write knows,
// so a swapped directory makes the move fail rather than land elsewhere.
func replaceFile(_ *os.Root, dir, temp, name string) error {
	return Rename(filepath.Join(dir, temp), filepath.Join(dir, name))
}

// renameRetry bounds how long Rename retries while another program, such as
// an antivirus scanner, briefly holds a file in a way that blocks it.
const renameRetry = 2 * time.Second

// Rename moves from to to, replacing to, durably. Like rename(2), it
// replaces a symlink at to rather than writing through it.
//
// It uses MoveFileEx with MOVEFILE_REPLACE_EXISTING and, so that it returns
// only once the move is on disk, MOVEFILE_WRITE_THROUGH, which takes the
// place of a directory sync. MoveFileEx cannot replace a file that another
// handle has open, even one that shares delete access, such as a reader of
// the state file. Then it renames with POSIX semantics (Windows 10 and
// later on NTFS), which unlinks the open file's name at once, and flushes
// the renamed file, which commits NTFS's journal record of the rename.
// Where neither works yet, it retries boundedly.
func Rename(from, to string) error {
	fromp, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	top, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(renameRetry)
	for delay := 10 * time.Millisecond; ; delay = min(2*delay, 200*time.Millisecond) {
		ok, _, err := procMoveFileExW.Call(uintptr(unsafe.Pointer(fromp)), uintptr(unsafe.Pointer(top)), movefileReplaceExisting|movefileWriteThrough)
		if ok != 0 {
			return nil
		}
		if busy(err) {
			if err = posixRename(from, to); err == nil {
				return nil
			}
		}
		if !busy(err) && !unsupported(err) || time.Now().After(deadline) {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
		}
		time.Sleep(delay)
	}
}

// busy reports whether err says another handle has the file open.
func busy(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED) || errors.Is(err, errorSharingViolation)
}

// unsupported reports whether err says the file system cannot rename with
// POSIX semantics.
func unsupported(err error) bool {
	return errors.Is(err, errorInvalidParameter) || errors.Is(err, errorNotSupported) || errors.Is(err, errorInvalidFunction)
}

// fileRenameInfo is FILE_RENAME_INFO, with the flags of FileRenameInfoEx.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  syscall.Handle
	FileNameLength uint32 // bytes
	FileName       [1]uint16
}

// posixRename renames from to to with POSIX semantics, replacing to even
// while it is open, and flushes the renamed file.
func posixRename(from, to string) error {
	f, err := createFile(from, accessDelete|syscall.GENERIC_WRITE|synchronize, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	if err != nil {
		return err
	}
	defer f.Close()
	name, err := syscall.UTF16FromString(to)
	if err != nil {
		return err
	}
	name = name[:len(name)-1] // FileNameLength excludes the terminating NUL
	offset := unsafe.Offsetof(fileRenameInfo{}.FileName)
	size := offset + uintptr(len(name)+1)*2
	buf := make([]uint64, (size+7)/8) // 8-byte aligned, zeroed
	info := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	info.Flags = fileRenameReplaceIfExists | fileRenamePosixSemantics
	info.FileNameLength = uint32(len(name) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	ok, _, err := procSetFileInformationByHandle.Call(f.Fd(), fileRenameInfoEx, uintptr(unsafe.Pointer(info)), size)
	if ok == 0 {
		return err
	}
	return f.Sync()
}

// syncDirectory does nothing: Windows cannot flush a directory handle, and
// NetShift's renames are written through instead (see replaceFile). NTFS
// journals the creation of new directory entries.
func syncDirectory(*os.File) error { return nil }

// lockRange returns the OVERLAPPED that addresses the one byte NetShift
// locks, far beyond any data. Windows locks are mandatory, so locking a
// byte of the content would block other readers and writers of it.
func lockRange() *syscall.Overlapped { return &syscall.Overlapped{OffsetHigh: 0x7FFFFFFF} }

// LockFile takes an exclusive lock on f without waiting (LockFileEx). An
// error wrapping ERROR_LOCK_VIOLATION means another handle holds it.
func LockFile(f *os.File) error {
	ok, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(lockRange())))
	if ok == 0 {
		return err
	}
	return nil
}

// UnlockFile releases LockFile's lock. Closing f releases it as well, but
// Windows may take a while to do so.
func UnlockFile(f *os.File) error {
	ok, _, err := procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(lockRange())))
	if ok == 0 {
		return err
	}
	return nil
}

// IsLockViolation reports whether err says another handle holds the lock.
func IsLockViolation(err error) bool { return errors.Is(err, errorLockViolation) }

// TryLockFile takes LockFile's lock and reports whether it did. Closing f
// releases the lock.
func TryLockFile(f *os.File) bool { return LockFile(f) == nil }
