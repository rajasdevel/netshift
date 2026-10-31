package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rajasdevel/netshift/internal/store"
)

type runnerFunc func(context.Context, string, []string, []string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, program string, args, env []string) ([]byte, error) {
	return f(ctx, program, args, env)
}

// An apparently unchanged initial registry is not authority to skip subsequent
// reads. A peer can enroll or retire this identity while preflight is in flight.
func TestUnchangedReconciliationObservesConcurrentRegistryChange(t *testing.T) {
	for _, retire := range []bool{false, true} {
		name := "peer_enrollment"
		if retire {
			name = "own_retirement"
		}
		t.Run(name, func(t *testing.T) {
			e, cloud := deviceFixture(t)
			driveDevice(t, e, "8.8.4.4")
			a := e.Config.Actions["allow"]
			changed := false
			e.Runner = runnerFunc(func(ctx context.Context, program string, args, env []string) ([]byte, error) {
				if !changed && args[0] == "postgres" && args[3] == "list" {
					changed = true
					for _, n := range cloud.nsgs {
						d := DeviceRecord{Version: 2, Identity: "sam@desktop", IPs: []string{"1.1.1.1"}, Revision: 1}
						if retire {
							var err error
							d, err = parseDevice(n.Tags[deviceTag(a, e.Config.Identity, false)])
							if err != nil {
								t.Fatal(err)
							}
							d.Retired = true
							d.Revision++
						}
						raw, err := encodeDevice(d, a.Devices.HistoryLimit)
						if err != nil {
							t.Fatal(err)
						}
						n.Tags[deviceTag(a, d.Identity, retire)] = raw
					}
				}
				return cloud.Run(ctx, program, args, env)
			})
			err := e.runDevices(context.Background(), "allow", a, e.State.IP, false)
			if retire && !errors.Is(err, errIdentityRetired) || !retire && err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatal("concurrent change did not occur")
			}
			if retire {
				if !e.State.Action("allow").Retired {
					t.Fatal("missed remote retirement")
				}
				assertDeviceIPs(t, e, cloud, "9.9.9.9")
				own := devicePGTarget(e.Config, a.Targets[2], e.Config.Identity)
				if _, ok := cloud.pg[own.Server][own.Rule]; ok {
					t.Fatal("retired database access remains")
				}
			} else {
				assertDeviceIPs(t, e, cloud, "9.9.9.9", "8.8.4.4", "1.1.1.1")
			}
		})
	}
}

func TestUnchangedReconciliationPreservesUnresolvedIntentGuard(t *testing.T) {
	e, cloud := deviceFixture(t)
	driveDevice(t, e, "8.8.4.4")
	a := e.Config.Actions["allow"]
	target := a.Targets[0]
	slot := e.sharedState("allow", expectedResourceID(target)+"#")
	slot.Pending = &store.HistoryRecord{Status: "device_intent", ResourceID: expectedResourceID(target), AfterSources: []string{"8.8.4.4", "9.9.9.9", "4.2.2.2"}}
	if err := e.save(); err != nil {
		t.Fatal(err)
	}
	before := 0
	for _, count := range cloud.writes {
		before += count
	}
	err := e.runDevices(context.Background(), "allow", a, e.State.IP, false)
	if err == nil || !strings.Contains(err.Error(), "lost an unrelated source") {
		t.Fatalf("guard bypassed: %v", err)
	}
	after := 0
	for _, count := range cloud.writes {
		after += count
	}
	if slot.Pending == nil || before != after {
		t.Fatal("unresolved operation was cleared or caused a write")
	}
}
