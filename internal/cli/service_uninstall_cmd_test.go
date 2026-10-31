package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/service"
	"github.com/rajasdevel/netshift/internal/store"
)

func TestUninstallPreviewAndApplyPreserveUserData(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			out := captureOutput(t)
			c, profile, host := serviceFixture(t, goos)
			s := specFor(t, c, profile, host)
			r := &serviceRunner{label: s.Label}
			if err := runServiceArgs(t, c, profile, host, r, "install", "--start"); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(host.Home, "state.json")
			others := []string{state, store.HistoryPath(state), filepath.Join(filepath.Dir(s.Path), "other.service")}
			for _, p := range others {
				if err := os.WriteFile(p, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			kept := map[string][]byte{}
			for _, p := range append(slices.Clip(others), s.Binary, s.Config, profile) {
				kept[p], _ = os.ReadFile(p)
			}
			r.calls = nil
			out.Reset()
			if err := runServiceArgs(t, c, profile, host, r, "uninstall"); err != nil {
				t.Fatal(err)
			}
			if len(r.calls) != 0 || !r.loaded {
				t.Fatalf("preview touched the service: %q", r.calls)
			}
			if !strings.Contains(out.String(), "Installed from: "+profile+"\n") || !strings.Contains(out.String(), "Use --apply") {
				t.Fatalf("preview: %s", out)
			}
			if _, err := os.Stat(s.Path); err != nil {
				t.Fatal("preview removed the definition")
			}
			if err := runServiceArgs(t, c, profile, host, r, "uninstall", "--apply"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(s.Path); !errors.Is(err, os.ErrNotExist) || r.loaded || !r.disabled {
				t.Fatalf("service not removed: %q", r.calls)
			}
			if goos == "darwin" {
				if !slices.Equal(r.verbs(), []string{"disable", "print", "bootout", "print"}) {
					t.Fatalf("darwin uninstall: %q", r.calls)
				}
				onlyTouches(t, r.calls, s.Domain+"/"+s.Label)
			} else if !slices.Equal(r.verbs(), []string{"disable", "daemon-reload"}) {
				t.Fatalf("linux uninstall: %q", r.calls)
			}
			for p, data := range kept {
				if now, err := os.ReadFile(p); err != nil || !bytes.Equal(now, data) {
					t.Fatalf("uninstall changed %s", p)
				}
			}
			r.calls = nil
			out.Reset()
			if err := runServiceArgs(t, c, profile, host, r, "uninstall", "--apply"); err != nil || !strings.Contains(out.String(), "nothing removed") {
				t.Fatal("not idempotent", err, out)
			}
		})
	}
}

// Profiles with one name share one service; uninstall from another profile
// file is refused unless --replace says to remove it anyway.
func TestUninstallRefusesServiceFromAnotherProfileFile(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			out := captureOutput(t)
			c, profile, host := serviceFixture(t, goos)
			s := specFor(t, c, profile, host)
			if err := runServiceArgs(t, c, profile, host, &serviceRunner{label: s.Label}, "install"); err != nil {
				t.Fatal(err)
			}
			definition, _ := os.ReadFile(s.Path)
			other := filepath.Join(t.TempDir(), "home.json")
			writeProfileCopy(t, other)
			for _, args := range [][]string{{"uninstall"}, {"uninstall", "--apply"}} {
				r := &serviceRunner{label: s.Label, loaded: true}
				err := runServiceArgs(t, c, other, host, r, args...)
				if err == nil || !strings.Contains(err.Error(), "installed from "+profile) || !strings.Contains(err.Error(), "--replace") {
					t.Fatalf("%q from another profile file: %v", args, err)
				}
				if now, _ := os.ReadFile(s.Path); len(r.calls) != 0 || !bytes.Equal(now, definition) {
					t.Fatalf("%q refusal touched the service: %q", args, r.calls)
				}
			}
			// A hard link to the installing profile is the same file.
			alias := filepath.Join(filepath.Dir(profile), "alias.json")
			if err := os.Link(profile, alias); err != nil {
				t.Fatal(err)
			}
			if err := runServiceArgs(t, c, alias, host, &serviceRunner{label: s.Label}, "uninstall"); err != nil {
				t.Fatal("alias refused:", err)
			}
			out.Reset()
			if err := runServiceArgs(t, c, other, host, &serviceRunner{label: s.Label}, "uninstall", "--replace"); err != nil || !strings.Contains(out.String(), "Installed from: "+profile) {
				t.Fatal(err, out)
			}
			r := &serviceRunner{label: s.Label, loaded: true}
			if err := runServiceArgs(t, c, other, host, r, "uninstall", "--apply", "--replace"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(s.Path); !errors.Is(err, os.ErrNotExist) || r.loaded {
				t.Fatal("--replace did not remove the service")
			}
		})
	}
}

func TestUninstallRefusesUnmanagedSymlinkAndOrphanService(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			captureOutput(t)
			c, profile, host := serviceFixture(t, goos)
			s := specFor(t, c, profile, host)
			r := &serviceRunner{label: s.Label, loaded: true}
			if err := runServiceArgs(t, c, profile, host, r, "uninstall", "--apply"); err == nil || !r.loaded {
				t.Fatal("stopped an unverified orphan", err)
			}
			// No definite answer is not "nothing loaded".
			r = &serviceRunner{label: s.Label, answerErr: context.DeadlineExceeded}
			if err := runServiceArgs(t, c, profile, host, r, "uninstall", "--apply"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("unanswered status read as not loaded:", err)
			}
			if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(s.Path, []byte("someone else's service"), 0600)
			r = &serviceRunner{label: s.Label, loaded: true}
			if runServiceArgs(t, c, profile, host, r, "uninstall", "--apply", "--replace") == nil || len(r.calls) != 0 {
				t.Fatal("removed an unmanaged definition")
			}
			target := filepath.Join(t.TempDir(), "target")
			raw, _ := service.Render(s)
			_ = os.WriteFile(target, raw, 0600)
			_ = os.Remove(s.Path)
			if err := os.Symlink(target, s.Path); err != nil {
				t.Fatal(err)
			}
			if runServiceArgs(t, c, profile, host, r, "uninstall", "--apply") == nil || len(r.calls) != 0 {
				t.Fatal("followed a symlink")
			}
		})
	}
}

// A job whose state launchd does not report (a timeout) keeps its
// definition: uninstall stops before removing anything.
func TestUninstallKeepsDefinitionWhenStopIsUncertain(t *testing.T) {
	captureOutput(t)
	c, profile, host := serviceFixture(t, "darwin")
	s := specFor(t, c, profile, host)
	if err := runServiceArgs(t, c, profile, host, &serviceRunner{label: s.Label}, "install", "--start"); err != nil {
		t.Fatal(err)
	}
	r := &serviceRunner{label: s.Label, loaded: true, answerErr: context.DeadlineExceeded}
	if err := runServiceArgs(t, c, profile, host, r, "uninstall", "--apply"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path); err != nil || slices.Contains(r.verbs(), "bootout") {
		t.Fatalf("definition removed or job booted out without an answer: %q", r.calls)
	}
}
