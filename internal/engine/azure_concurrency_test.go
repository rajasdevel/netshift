package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/store"
)

// Independent clients cross an HTTP boundary. Each fake Azure request is
// serialized, but whole read/plan/write sequences deliberately overlap.
type apiRunner struct {
	url    string
	client *http.Client
}

func (r apiRunner) Run(ctx context.Context, program string, args, env []string) ([]byte, error) {
	data, _ := json.Marshal(args)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	response, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New(string(data))
	}
	return data, nil
}

type concurrentAPI struct {
	mu     sync.Mutex
	cloud  *deviceCloud
	gateMu sync.Mutex
	gate   chan struct{}
	gated  map[string]bool
}

func (a *concurrentAPI) serve(w http.ResponseWriter, r *http.Request) {
	var args []string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&args); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	var wait chan struct{}
	if len(args) > 0 && args[0] == "tag" && argValue(args, "--operation") == "Merge" {
		key, _, _ := strings.Cut(argValue(args, "--tags"), "=")
		a.gateMu.Lock()
		if a.gate != nil && !a.gated[key] {
			a.gated[key] = true
			wait = a.gate
			if len(a.gated) == 2 {
				close(a.gate)
				a.gate = nil
			}
		}
		a.gateMu.Unlock()
	}
	if wait != nil {
		select {
		case <-wait:
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			http.Error(w, "second client never reached the write barrier", 500)
			return
		}
	}
	a.mu.Lock()
	data, err := a.cloud.Run(r.Context(), "az", args, nil)
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
func concurrentFixture(t *testing.T) (*Engine, *Engine, *deviceCloud, *concurrentAPI) {
	t.Helper()
	first, cloud := deviceFixture(t)
	driveDevice(t, first, "8.8.4.4")
	second := deviceEngine(t, first.Config, cloud, "sam@desktop")
	driveDevice(t, second, "1.1.1.1")
	api := &concurrentAPI{cloud: cloud, gate: make(chan struct{}), gated: map[string]bool{}}
	server := httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(server.Close)
	runner := apiRunner{url: server.URL, client: server.Client()}
	first.Runner = runner
	second.Runner = runner
	return first, second, cloud, api
}
func runConcurrent(t *testing.T, tasks ...func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := make(chan struct{})
	result := make(chan error, len(tasks))
	for _, task := range tasks {
		go func(fn func(context.Context) error) {
			<-start
			var err error
			for range 6 {
				if err = fn(ctx); err == nil {
					result <- nil
					return
				}
				if ctx.Err() != nil {
					break
				}
			}
			result <- err
		}(task)
	}
	close(start)
	for range tasks {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
}
func TestConcurrentClientsKeepBothNewIPsAndReusePGNames(t *testing.T) {
	first, second, cloud, api := concurrentFixture(t)
	first.State.IP = "208.67.222.222"
	second.State.IP = "4.2.2.2"
	runConcurrent(t, func(ctx context.Context) error {
		return first.runDevices(ctx, "allow", first.Config.Actions["allow"], first.State.IP, false)
	}, func(ctx context.Context) error {
		return second.runDevices(ctx, "allow", second.Config.Actions["allow"], second.State.IP, false)
	})
	assertDeviceIPs(t, first, cloud, "9.9.9.9", first.State.IP, second.State.IP)
	if len(api.gated) < 2 {
		t.Fatal("clients did not overlap at the write barrier")
	}
	for _, e := range []*Engine{first, second} {
		name := devicePGTarget(e.Config, e.Config.Actions["allow"].Targets[2], e.Config.Identity).Rule
		if cloud.writes["pg:create:database:"+name] != 1 {
			t.Fatal("PG rule recreated", name)
		}
	}
	for _, e := range []*Engine{first, second} {
		rows, err := store.ReadHistory(store.HistoryPath(e.StatePath), 1000, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Identity != e.Config.Identity {
				t.Fatal("mixed local audit identities", r.Identity)
			}
		}
	}
}
func TestConcurrentRetirementAndIPChangeConverge(t *testing.T) {
	first, second, cloud, _ := concurrentFixture(t)
	second.State.IP = "4.2.2.2"
	runConcurrent(t, func(ctx context.Context) error {
		return first.retireDevice(ctx, "allow", first.Config.Actions["allow"], second.Config.Identity)
	}, func(ctx context.Context) error {
		if err := second.runDevices(ctx, "allow", second.Config.Actions["allow"], second.State.IP, false); !errors.Is(err, errIdentityRetired) {
			return err
		}
		return nil
	})
	// A sleeping/losing writer observes the tombstone on its next reconciliation.
	if err := second.runDevices(context.Background(), "allow", second.Config.Actions["allow"], second.State.IP, false); !errors.Is(err, errIdentityRetired) {
		t.Fatal(err)
	}
	assertDeviceIPs(t, first, cloud, "9.9.9.9", "8.8.4.4")
	own := devicePGTarget(second.Config, second.Config.Actions["allow"].Targets[2], second.Config.Identity)
	if _, ok := cloud.pg[own.Server][own.Rule]; ok {
		t.Fatal("retired PostgreSQL access remains")
	}
	if !second.State.Action("allow").Retired {
		t.Fatal("retired client remains active")
	}
	reg, err := first.loadDevices(context.Background(), first.Config.Actions["allow"])
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Devices[second.Config.Identity].Retired {
		t.Fatal(fmt.Sprint(reg.Devices))
	}
}
