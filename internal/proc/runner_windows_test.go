//go:build windows

package proc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// helperEnv selects what the test binary does when a test runs it as a
// program: see runHelper.
const helperEnv = "NETSHIFT_PROC_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(runHelper(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// runHelper is the test binary acting as a hook or as az.cmd's python.exe.
func runHelper(mode string, args []string) int {
	switch mode {
	case "args": // print the arguments as received
		_ = json.NewEncoder(os.Stdout).Encode(args)
	case "exit3":
		return 3
	case "sleep":
		time.Sleep(30 * time.Second)
	case "flood":
		_, _ = os.Stdout.Write(make([]byte, 3_000_000))
	case "spawn": // leave a child that would run for 30 seconds
		child := exec.Command(os.Args[0], args[0])
		child.Env = append(os.Environ(), helperEnv+"=touch-later")
		if args[1] == "inherit" {
			child.Stdout = os.Stdout // keeps the hook's output open
		}
		if err := child.Start(); err != nil {
			return 2
		}
		_, _ = fmt.Fprintf(os.Stdout, "started %d\n", child.Process.Pid)
	case "touch-later":
		time.Sleep(30 * time.Second)
		_ = os.WriteFile(args[0], nil, 0600)
	}
	return 0
}

func helper(mode string) []string { return []string{helperEnv + "=" + mode} }

// A hook's children are in its job, which is killed when the hook exits,
// whether or not they hold its output open.
func TestRunnerStopsChildrenInTheJob(t *testing.T) {
	for _, output := range []string{"inherit", "none"} {
		marker := filepath.Join(t.TempDir(), "survivor")
		start := time.Now()
		out, err := (Exec{}).Run(t.Context(), os.Args[0], []string{marker, output}, helper("spawn"))
		var pid uint32
		if _, scanErr := fmt.Sscanf(string(out), "started %d\n", &pid); err != nil || scanErr != nil || time.Since(start) > WaitDelay/2 {
			t.Fatalf("%s: %q %v after %v", output, out, err, time.Since(start))
		}
		// The child is gone once Run returns, or very soon after.
		child, err := syscall.OpenProcess(syscall.SYNCHRONIZE|processQueryLimitedInformation|processTerminate, false, pid)
		if err != nil {
			continue // already gone
		}
		if event, _ := syscall.WaitForSingleObject(child, 5000); event != syscall.WAIT_OBJECT_0 {
			var inJob int32
			_, _, _ = procIsProcessInJob.Call(uintptr(child), 0, uintptr(unsafe.Pointer(&inJob)))
			_ = syscall.TerminateProcess(child, 1)
			t.Errorf("%s: child %d outlived its hook (in a job: %t)", output, pid, inJob != 0)
		}
		_ = syscall.CloseHandle(child)
	}
}

const processQueryLimitedInformation = 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION

var procIsProcessInJob = kernel32.NewProc("IsProcessInJob")

func TestRunnerTimeoutKillsTheJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := (Exec{}).Run(ctx, os.Args[0], nil, helper("sleep"))
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestRunnerBoundsOutputAndReportsExitStatus(t *testing.T) {
	if data, err := (Exec{}).Run(t.Context(), os.Args[0], nil, helper("flood")); err == nil || !strings.Contains(err.Error(), "exceeded the output limit") || data != nil {
		t.Fatalf("len=%d err=%v", len(data), err)
	}
	if _, err := (Exec{}).Run(t.Context(), os.Args[0], nil, helper("exit3")); err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("exit status: %v", err)
	}
}

// awkward holds arguments that cmd.exe or the C runtime would misread
// without quoting.
var awkward = []string{"plain", "two words", "&calc", "a|b", "<in>", "(x)", ")", "^caret", `trail\`, `trail\\`,
	"", `C:\Program Files\x\`, "{name:name,id:id}", "[?name=='x']", "semi;colon", "comma,x", "eq=ual", "ü€😀", "--query",
	`netshift.home.device.x={"v":1,"id":"sam@host","ips":["8.8.8.8","8.8.4.4"]}`, `say "hi" \"there\"`, `"`}

// An .exe receives its arguments literally.
func TestRunnerPassesLiteralArguments(t *testing.T) {
	out, err := (Exec{}).Run(t.Context(), os.Args[0], awkward, helper("args"))
	var got []string
	if err != nil || json.Unmarshal(out, &got) != nil || !slices.Equal(got, awkward) {
		t.Fatalf("%q %v", out, err)
	}
}

// fakeAZ writes a batch file shaped like the Azure CLI's az.cmd, which
// passes its arguments on with %* inside a parenthesized IF block, next to a
// copy of the test binary standing in for python.exe.
func fakeAZ(t *testing.T) string {
	dir := t.TempDir()
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "python.exe"), self, 0700); err != nil {
		t.Fatal(err)
	}
	script := "::\r\n:: A stand-in for the Azure CLI's az.cmd\r\n::\r\n\r\n" +
		"@IF EXIST \"%~dp0\\python.exe\" (\r\n  SET AZ_INSTALLER=MSI\r\n  \"%~dp0\\python.exe\" %*\r\n) ELSE (\r\n" +
		"  echo Failed to load python executable.\r\n  exit /b 1\r\n)\r\n"
	if err = os.WriteFile(filepath.Join(dir, "az.cmd"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A batch file receives each argument literally, whether it is named by its
// path, by its path without the extension, or through PATH.
func TestRunnerPassesLiteralArgumentsThroughBatchFiles(t *testing.T) {
	dir := fakeAZ(t)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, program := range []string{filepath.Join(dir, "az.cmd"), filepath.Join(dir, "az"), "az"} {
		out, err := (Exec{}).Run(t.Context(), program, awkward, helper("args"))
		var got []string
		if err != nil || json.Unmarshal(out, &got) != nil || !slices.Equal(got, awkward) {
			t.Fatalf("%s: %q %v", program, out, err)
		}
	}
	if _, err := (Exec{}).Run(t.Context(), filepath.Join(dir, "az.cmd"), nil, helper("exit3")); err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("batch exit status: %v", err)
	}
}

// What cmd.exe would interpret is refused before anything runs: the
// refusal comes from building the command line, before a process exists,
// and the helper that would print its arguments prints nothing.
func TestRunnerRefusesUnsafeBatchArguments(t *testing.T) {
	dir := fakeAZ(t)
	for _, bad := range []string{`a"b&c`, "%PATH%", "!x!", "a\r\nb"} {
		out, err := (Exec{}).Run(t.Context(), filepath.Join(dir, "az.cmd"), []string{"ok", bad}, helper("args"))
		if err == nil || !strings.Contains(err.Error(), "cannot run") || len(out) != 0 {
			t.Fatalf("%q: %q %v", bad, out, err)
		}
	}
}

// An unusable home directory is not used as the working directory.
func TestRunnerIgnoresUnusableHome(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, home := range []string{filepath.Join(t.TempDir(), "missing"), file} {
		t.Setenv("USERPROFILE", home)
		if dir := workingDir(); dir != "" {
			t.Errorf("USERPROFILE=%s: working directory %q", home, dir)
		}
		if _, err := (Exec{}).Run(t.Context(), os.Args[0], nil, helper("args")); err != nil {
			t.Errorf("USERPROFILE=%s: %v", home, err)
		}
	}
}
