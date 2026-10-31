//go:build windows

package proc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procThread32First            = kernel32.NewProc("Thread32First")
	procThread32Next             = kernel32.NewProc("Thread32Next")
	procOpenThread               = kernel32.NewProc("OpenThread")
	procResumeThread             = kernel32.NewProc("ResumeThread")
	procGetSystemDirectoryW      = kernel32.NewProc("GetSystemDirectoryW")
)

// Windows constants that package syscall does not define.
const (
	createSuspended = 0x00000004 // CREATE_SUSPENDED
	createNoWindow  = 0x08000000 // CREATE_NO_WINDOW

	jobObjectExtendedLimitInformation = 9      // JOBOBJECTINFOCLASS
	jobLimitDieOnUnhandledException   = 0x0400 // JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	jobLimitKillOnJobClose            = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

	processSetQuota     = 0x0100 // PROCESS_SET_QUOTA
	processTerminate    = 0x0001 // PROCESS_TERMINATE
	threadSuspendResume = 0x0002 // THREAD_SUSPEND_RESUME
	th32csSnapThread    = 0x0004 // TH32CS_SNAPTHREAD

	jobKilledExitCode = 1
)

// jobBasicLimitInformation is JOBOBJECT_BASIC_LIMIT_INFORMATION.
type jobBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

// jobExtendedLimitInformation is JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
type jobExtendedLimitInformation struct {
	BasicLimitInformation jobBasicLimitInformation
	IoInfo                [6]uint64 // IO_COUNTERS
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// threadEntry32 is THREADENTRY32.
type threadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// groupSys is the program's Job Object. The job kills its processes when
// its last handle closes, and NetShift holds the only one, so they cannot
// outlive NetShift either. A job allows no breakaway unless asked, so a
// program cannot move a child out of it.
type groupSys struct {
	mu  sync.Mutex
	job syscall.Handle // 0 once closed
}

// ContainProcess prepares cmd to start suspended, so that Start can put it
// in a new Job Object before it runs any code, and without a console window
// of its own. A .cmd or .bat program is rewritten to run through cmd.exe
// (see batchCommandLine). When the job cannot be created or an argument
// cannot be passed safely, the command fails to start rather than run
// without those guarantees.
func ContainProcess(cmd *exec.Cmd) *Group {
	g := &Group{cmd: cmd}
	if cmd.Err != nil {
		return g
	}
	attr := &syscall.SysProcAttr{CreationFlags: createSuspended | createNoWindow}
	if err := runBatchThroughCmd(cmd, attr); err != nil {
		cmd.Err = err
		return g
	}
	job, err := newJob()
	if err != nil {
		cmd.Err = fmt.Errorf("cannot create a job object for %s: %w", cmd.Path, err)
		return g
	}
	g.sys.job = job
	cmd.SysProcAttr = attr
	cmd.Cancel = func() error {
		g.sys.mu.Lock()
		defer g.sys.mu.Unlock()
		if g.sys.job == 0 {
			return os.ErrProcessDone
		}
		return terminateJob(g.sys.job)
	}
	return g
}

// start starts the suspended program, adds it to the job, and only then lets
// it run, so nothing it starts can be outside the job.
func (g *Group) start() error {
	if err := g.cmd.Start(); err != nil {
		return err
	}
	g.sys.mu.Lock()
	err := adopt(g.sys.job, uint32(g.cmd.Process.Pid))
	g.sys.mu.Unlock()
	if err != nil {
		_ = g.cmd.Process.Kill()
		_ = g.cmd.Wait()
		return fmt.Errorf("cannot contain %s in its job object: %w", g.cmd.Path, err)
	}
	return nil
}

// stop kills everything left in the job and closes it.
func (g *Group) stop() {
	g.sys.mu.Lock()
	defer g.sys.mu.Unlock()
	if g.sys.job != 0 {
		_ = terminateJob(g.sys.job)
		_ = syscall.CloseHandle(g.sys.job)
		g.sys.job = 0
	}
}

// newJob creates an unnamed, non-inheritable Job Object that kills its
// processes when it is closed. It also ends a crashing process at once
// rather than leaving it waiting on an error-reporting dialog.
func newJob() (syscall.Handle, error) {
	h, _, err := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return 0, err
	}
	job := syscall.Handle(h)
	var info jobExtendedLimitInformation
	info.BasicLimitInformation.LimitFlags = jobLimitKillOnJobClose | jobLimitDieOnUnhandledException
	ok, _, err := procSetInformationJobObject.Call(uintptr(job), jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if ok == 0 {
		_ = syscall.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// adopt assigns the suspended process pid to job and resumes it.
func adopt(job syscall.Handle, pid uint32) error {
	if job == 0 {
		return errors.New("the job object is closed")
	}
	h, err := syscall.OpenProcess(processSetQuota|processTerminate, false, pid)
	if err != nil {
		return err
	}
	ok, _, err := procAssignProcessToJobObject.Call(uintptr(job), uintptr(h))
	_ = syscall.CloseHandle(h)
	if ok == 0 {
		return err
	}
	return resumeThreads(pid)
}

// resumeThreads resumes the threads of process pid. A process created
// suspended has one: its main thread.
func resumeThreads(pid uint32) error {
	snapshot, err := syscall.CreateToolhelp32Snapshot(th32csSnapThread, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(snapshot)
	entry := threadEntry32{Size: uint32(unsafe.Sizeof(threadEntry32{}))}
	resumed := 0
	for ok, _, _ := procThread32First.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry))); ok != 0; ok, _, _ = procThread32Next.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry))) {
		if entry.OwnerProcessID != pid {
			continue
		}
		thread, _, err := procOpenThread.Call(threadSuspendResume, 0, uintptr(entry.ThreadID))
		if thread == 0 {
			return err
		}
		count, _, err := procResumeThread.Call(thread)
		_ = syscall.CloseHandle(syscall.Handle(thread))
		if count == 0xFFFFFFFF {
			return err
		}
		resumed++
	}
	if resumed == 0 {
		return fmt.Errorf("found no thread of process %d to resume", pid)
	}
	return nil
}

// terminateJob kills every process in job.
func terminateJob(job syscall.Handle) error {
	if ok, _, err := procTerminateJobObject.Call(uintptr(job), jobKilledExitCode); ok == 0 {
		return err
	}
	return nil
}

// runBatchThroughCmd points cmd at cmd.exe, with a command line built by
// batchCommandLine in attr, when cmd's program is a .cmd or .bat file.
// Other programs are left as they are.
func runBatchThroughCmd(cmd *exec.Cmd, attr *syscall.SysProcAttr) error {
	// exec.Command resolves a PATH name to its file, extension included, but
	// keeps an absolute path given without one; LookPath resolves both.
	resolved, err := exec.LookPath(cmd.Path)
	if err != nil {
		return nil // Start reports it
	}
	if ext := strings.ToLower(filepath.Ext(resolved)); ext != ".cmd" && ext != ".bat" {
		return nil
	}
	dir, err := systemDirectory()
	if err != nil {
		return fmt.Errorf("cannot locate cmd.exe to run %s: %w", resolved, err)
	}
	cmdExe := filepath.Join(dir, "cmd.exe")
	line, err := batchCommandLine(cmdExe, resolved, cmd.Args[1:])
	if err != nil {
		return err
	}
	cmd.Path = cmdExe
	attr.CmdLine = line
	return nil
}

// systemDirectory returns the Windows system directory, such as
// C:\Windows\System32, from the system rather than the environment.
func systemDirectory() (string, error) {
	buf := make([]uint16, syscall.MAX_PATH)
	for {
		n, _, err := procGetSystemDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		switch {
		case n == 0:
			return "", err
		case int(n) > len(buf):
			buf = make([]uint16, n)
			continue
		}
		return syscall.UTF16ToString(buf[:n]), nil
	}
}

// searchableDir reports whether dir is a directory. Windows has no separate
// permission to enter a directory one can see.
func searchableDir(dir string) bool {
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}
