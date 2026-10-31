package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/rajasdevel/netshift/internal/cmdline"
	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/store"
)

// errIdentityRetired reports that this identity has a retirement marker. Its
// cleanup has already run. The CLI reports it; watch treats it as the normal
// end of the identity's work, not as a failure.
var errIdentityRetired = errors.New("identity is retired; use devices activate")

// errMarkerIncomplete reports a retirement marker that does not list every
// address the registry holds for the retired identity. Its access is still
// removed, but its active record, which lists the missing addresses, stays.
var errMarkerIncomplete = errors.New("retirement marker cannot list every address")

// observeRetirement finishes this identity's own retirement after a registry
// read showed its marker, and records it in local state.
func (e *Engine) observeRetirement(ctx context.Context, name string, a config.ActionConfig, id string) error {
	if err := e.retireDevice(ctx, name, a, id); err != nil {
		return err
	}
	s := e.State.Action(name)
	s.Retired = true
	s.Pending = nil
	e.Log.Log("identity_retired", map[string]any{"identity": id})
	if err := e.save(); err != nil {
		return err
	}
	return errIdentityRetired
}

// cleanupRetiredDevice removes what a retired identity alone still holds:
// its addresses from every registry NSG rule and its PostgreSQL rules. Every
// target is visited even after a failure, so database access is revoked even
// when an NSG rule needs inspection; the failures are joined.
func (e *Engine) cleanupRetiredDevice(ctx context.Context, name string, a config.ActionConfig, id string, reg deviceRegistry) error {
	if !reg.Devices[id].Retired {
		return errors.New("retirement marker is required before cleanup")
	}
	p := devicePass{mode: modeRetire, desired: e.State.IP, retired: id}
	var failures []error
	for _, t := range a.Targets {
		var err error
		if t.Kind == config.KindNSG {
			err = e.reconcileDeviceNSG(ctx, name, a, t, reg, p)
		} else {
			own := devicePGTarget(e.Config, t, id)
			err = e.deleteDevicePG(ctx, name, a, own, id, reg.Histories[id], modeRetire)
			if id == a.Devices.LegacyIdentity && !strings.EqualFold(t.Rule, own.Rule) {
				err = errors.Join(err, e.deleteDevicePG(ctx, name, a, t, id, reg.Histories[id], modeRetire))
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", t.ID, err))
		}
	}
	return errors.Join(failures...)
}

// retireDevice retires id: it writes the retirement marker, extends it until
// it covers every address the registry holds for id, removes id's access,
// and only then deletes id's active record. The marker stays as the durable
// prohibition against an old watcher resurrecting the registration. Records
// of other identities that cannot be used are skipped, never acted on.
//
// Access is removed even when retirement cannot complete: when the marker
// cannot list every address of id (errMarkerIncomplete), or when a skipped
// record keeps an address of id allowed (see retainedRetiredIPs). The active
// record then stays, as after any failed cleanup, so the registry still
// lists every address of id and the pair marks the retirement unfinished;
// the error is returned once every target has been visited.
func (e *Engine) retireDevice(ctx context.Context, name string, a config.ActionConfig, id string) error {
	user, _, _ := strings.Cut(id, "@")
	localUser, _, _ := strings.Cut(e.Config.Identity, "@")
	if user != localUser {
		return errors.New("retire is restricted to this local username; another user must retire their own identity")
	}
	reg, err := e.readRetiring(ctx, a, id)
	if err != nil {
		return err
	}
	if _, ok := reg.Devices[id]; !ok {
		return fmt.Errorf("identity %s is not enrolled", id)
	}
	// What the registry lists for id now; a reread after the marker write
	// lists it too, so the marker must cover it.
	registry := slices.Clone(reg.Histories[id])
	if id == e.Config.Identity {
		local, err := e.ownDeviceHistory(name, a, reg)
		if err != nil {
			return err
		}
		reg.Histories[id] = uniqueIPs(append(reg.Histories[id], local...))
	}
	// Cleanup removes everything known now, even what the marker cannot hold.
	known := slices.Clone(reg.Histories[id])
	tomb, err := e.markRetired(ctx, name, a, id, reg)
	if err != nil {
		return err
	}
	reg, incomplete := e.settleRetirement(ctx, name, a, id, reg, tomb, registry, known)
	if incomplete != nil && !errors.Is(incomplete, errMarkerIncomplete) {
		return incomplete
	}
	if err = errors.Join(e.cleanupRetiredDevice(ctx, name, a, id, reg), e.checkRetained(name, a, id, reg), incomplete); err != nil {
		return err
	}
	if err = e.dropActiveRecord(ctx, name, a, id, reg); err != nil {
		return err
	}
	if id == e.Config.Identity && e.Apply {
		s := e.State.Action(name)
		s.Retired = true
		s.Pending = nil
		s.LastError = ""
	}
	return e.save()
}

// retainedRetiredIPs returns the addresses of id that a registry rule in reg
// still allows after cleanup only because a skipped record mentions them:
// cleanup neither adds nor removes such an address (see deviceRegistry). An
// address that an active identity is at is needed and not included.
func retainedRetiredIPs(reg deviceRegistry, a config.ActionConfig, id string) []string {
	if len(reg.Protected) == 0 {
		return nil
	}
	active := reg.activeIPs()
	var retained []string
	for _, t := range a.Targets {
		if t.Kind != config.KindNSG {
			continue
		}
		r, ok := findNSGRule(reg.NSGs[strings.ToLower(config.NSGResourceID(t))], t)
		if !ok {
			continue
		}
		for _, source := range r.sourceList() {
			ip, err := singleIP(source)
			if err == nil && containsIP(reg.Histories[id], ip) && containsIP(reg.Protected, ip) && !containsIP(active, ip) {
				retained = append(retained, ip)
			}
		}
	}
	return uniqueIPs(retained)
}

// checkRetained logs and reports the addresses of retired id that stay
// allowed after cleanup (see retainedRetiredIPs), so that retirement does
// not exit 0 while the retired device keeps access.
func (e *Engine) checkRetained(name string, a config.ActionConfig, id string, reg deviceRegistry) error {
	retained := retainedRetiredIPs(reg, a, id)
	if len(retained) == 0 {
		return nil
	}
	e.Log.Log("retired_address_retained", map[string]any{"action": name, "identity": id, "ips": retained})
	return fmt.Errorf("%s: %v stays allowed because a registry record that cannot be read mentions it; inspect the device_record_skipped records, then retry retirement", id, retained)
}

// dropActiveRecord deletes id's active record from every registry NSG, once
// its retirement marker covers it and cleanup is complete. A dry run wrote no
// marker, so it previews the deletion from reg instead.
func (e *Engine) dropActiveRecord(ctx context.Context, name string, a config.ActionConfig, id string, reg deviceRegistry) error {
	key := deviceTag(a, id, false)
	for _, t := range config.NSGGroups(a) {
		if e.Apply {
			if err := e.writeDeviceTag(ctx, name, a, t, tagWrite{key: key, owner: id, mode: modeRetire}); err != nil {
				return err
			}
			continue
		}
		if _, before, err := tagValue(reg.NSGs[strings.ToLower(config.NSGResourceID(t))].Tags, key); err == nil && before != "" {
			e.Log.Log("would_update_device_tag", map[string]any{"nsg": t.NSG, "identity": id, "tag": key, "before": before, "after": ""})
		}
	}
	return nil
}

// readRetiring reads the registry for retiring id: id's records must be
// usable, and unusable records of others are logged and skipped.
func (e *Engine) readRetiring(ctx context.Context, a config.ActionConfig, id string) (deviceRegistry, error) {
	reg, err := e.readRegistry(ctx, a, id)
	if err != nil {
		return reg, err
	}
	for _, s := range reg.Skipped {
		e.Log.Log("device_record_skipped", map[string]any{"nsg": s.NSG, "tag": s.Tag, "error": s.Err.Error(), "retiring": id})
	}
	return reg, nil
}

// planTombstone builds id's retirement marker from reg. Its addresses, newest
// first, are id's current address and its pinned addresses (see
// pinnedSources; these must fit), then those of id's active records, then
// those of its current record, then the rest of its history, up to the
// history limit. The revision grows whenever the marker changes, and only
// then.
func planTombstone(reg deviceRegistry, a config.ActionConfig, id string) (DeviceRecord, string, error) {
	current := reg.Devices[id]
	history := reg.Histories[id]
	var active []string
	for _, t := range config.NSGGroups(a) {
		n := reg.NSGs[strings.ToLower(config.NSGResourceID(t))]
		if _, raw, err := tagValue(n.Tags, deviceTag(a, id, false)); err == nil && raw != "" {
			if d, err := parseDevice(raw); err == nil {
				active = append(active, d.IPs...)
			}
		}
	}
	pinned := pinnedSources(reg, a, id, current.IPs[0], history)
	if len(pinned) > a.Devices.HistoryLimit {
		return current, "", errors.New("retirement history cannot fit all owned sources; inspect before cleanup")
	}
	d := DeviceRecord{Version: 2, Identity: id, Retired: true, Revision: current.Revision + 1}
	if d.Revision == 0 {
		return current, "", errors.New("device revision overflow")
	}
	d.IPs = uniqueIPs(slices.Concat(pinned, active, current.IPs, history))
	raw, err := encodeDevice(d, a.Devices.HistoryLimit)
	if err != nil {
		return d, "", err
	}
	if d, err = parseDevice(raw); err != nil {
		return d, "", err
	}
	if current.Retired && slices.Equal(current.IPs, d.IPs) {
		// An unchanged marker keeps its revision, so a rerun writes nothing.
		d = current
		if raw, err = encodeDevice(d, a.Devices.HistoryLimit); err != nil {
			return d, "", err
		}
	}
	if !containsAll(d.IPs, pinned) {
		return d, "", errors.New("retirement tag cannot retain every owned source")
	}
	return d, raw, nil
}

// markRetired writes id's retirement marker, planned from reg, to every
// registry NSG.
func (e *Engine) markRetired(ctx context.Context, name string, a config.ActionConfig, id string, reg deviceRegistry) (DeviceRecord, error) {
	tomb, raw, err := planTombstone(reg, a, id)
	if err != nil {
		return tomb, err
	}
	for _, t := range config.NSGGroups(a) {
		if err = e.writeDeviceTag(ctx, name, a, t, tagWrite{key: deviceTag(a, id, true), value: raw, owner: id, mode: modeRetire}); err != nil {
			return tomb, err
		}
	}
	return tomb, nil
}

// settleRetirement rereads the registry after the marker write. A writer
// that raced the marker may have added an address to id's active record; the
// marker is rewritten, a bounded number of times, until it lists every
// address the registry holds for id. The returned registry's history for id
// also includes known, for cleanup.
//
// A dry run cannot reread. It previews against reg as a reread would show it
// after the planned marker tomb was written: tomb, with id's history the
// union of tomb and registry, the addresses id's records listed before. It
// cannot rewrite the marker, so a gap is reported at once.
//
// When the marker cannot cover the registry, the error wraps
// errMarkerIncomplete and the returned registry is still the one to clean up.
func (e *Engine) settleRetirement(ctx context.Context, name string, a config.ActionConfig, id string, reg deviceRegistry, tomb DeviceRecord, registry, known []string) (deviceRegistry, error) {
	for attempt := 1; ; attempt++ {
		if e.Apply {
			var err error
			if reg, err = e.readRetiring(ctx, a, id); err != nil {
				return reg, err
			}
		} else {
			reg.Devices[id] = tomb
			reg.Histories[id] = uniqueIPs(slices.Concat(tomb.IPs, registry))
		}
		marker := reg.Devices[id]
		if !marker.Retired {
			return reg, errors.New("retirement marker disappeared, perhaps through a concurrent activation; retry")
		}
		missing := slices.DeleteFunc(slices.Clone(reg.Histories[id]), func(ip string) bool { return containsIP(marker.IPs, ip) })
		reg.Histories[id] = uniqueIPs(slices.Concat(reg.Histories[id], known))
		if len(missing) == 0 {
			return reg, nil
		}
		if !e.Apply {
			return reg, fmt.Errorf("%w of %s within history_limit; it would lack %v, so its active record would be kept", errMarkerIncomplete, id, missing)
		}
		if attempt == 3 {
			return reg, fmt.Errorf("%w of %s: its device record kept changing during retirement; retry", errMarkerIncomplete, id)
		}
		next, err := e.markRetired(ctx, name, a, id, reg)
		if err != nil {
			return reg, err
		}
		if slices.Equal(next.IPs, marker.IPs) {
			return reg, fmt.Errorf("%w of %s within history_limit; it lacks %v, so its active record was kept; inspect its records before retrying", errMarkerIncomplete, id, missing)
		}
		e.Log.Log("retirement_marker_extended", map[string]any{"identity": id, "ips": next.IPs})
	}
}

// activateDevice removes this identity's retirement marker and stale active
// records from every registry NSG, after a read showed the marker. It is a
// deliberate self-only operation, never part of watch; enrollment follows.
func (e *Engine) activateDevice(ctx context.Context, name string, a config.ActionConfig) error {
	reg, err := e.loadDevices(ctx, a)
	if err != nil {
		return err
	}
	id := e.Config.Identity
	d, found := reg.Devices[id]
	if !found || !d.Retired {
		return errors.New("identity has no retirement marker; use devices enroll")
	}
	// Removing markers is a deliberate self-only operation, never part of watch.
	// Remove stale active records first to avoid conflicting revision history.
	for _, key := range []string{deviceTag(a, id, false), deviceTag(a, id, true)} {
		for _, t := range config.NSGGroups(a) {
			if err = e.writeDeviceTag(ctx, name, a, t, tagWrite{key: key, owner: id, mode: modeEnroll}); err != nil {
				return err
			}
		}
	}
	e.State.Action(name).Retired = false
	// Preserve ownership when the last cloud marker has just been removed.
	if err = e.record(store.HistoryRecord{Status: statusMetadataVerified, Action: name, Target: "identity", Identity: id, IP: d.IPs[0], Tag: deviceTag(a, id, false), AfterValue: mustDeviceJSON(d)}); err != nil {
		return err
	}
	return e.save()
}

// mustDeviceJSON is d's JSON. A device record always marshals.
func mustDeviceJSON(d DeviceRecord) string { b, _ := json.Marshal(d); return string(b) }

// DevicesOptions are the devices command's options.
type DevicesOptions struct {
	apply  bool
	action string
}

// DevicesCommandLine defines the devices command's options, for parsing and
// for help.
func DevicesCommandLine(o *DevicesOptions) *cmdline.Line {
	f := cmdline.New("devices", "[--config FILE] devices list | enroll | retire USER@HOST | activate [--action NAME] [--apply]",
		"List, enroll, retire, or reactivate Azure device identities.")
	f.BoolVar(&o.apply, "apply", false, "allow cloud writes")
	f.StringVar(&o.action, "action", "", "the device action `NAME` (required when there are several)")
	return f
}

// HandleDevices runs the devices command: list, enroll, retire USER@HOST, or
// activate one device action. Cloud writes need --apply, and then the
// profile's state lock, so the service must be stopped first.
func HandleDevices(ctx context.Context, c config.Config, statePath string, args []string, out io.Writer, log eventlog.Logger) error {
	var opts DevicesOptions
	f := DevicesCommandLine(&opts)
	positional, err := f.ParseArgs(args)
	if err != nil {
		return err
	}
	if !config.HasDevices(c) {
		return errors.New("this profile has no device action")
	}
	operation, id, err := devicesOperation(f, c, positional)
	if err != nil {
		return err
	}
	a, err := devicesAction(f, c, &opts)
	if err != nil {
		return err
	}
	if operation == "list" && opts.apply {
		return f.Errorf("devices list is read-only")
	}
	// A CLI writer shares the same local state lock as the watcher. The service
	// must be stopped explicitly before enrollment/retirement on this host.
	if opts.apply {
		unlock, err := store.Lock(statePath)
		if err != nil {
			return fmt.Errorf("stop this profile's service before a device operation: %w", err)
		}
		defer unlock()
	}
	state, err := store.Load(statePath)
	if err != nil {
		return err
	}
	if err = BindIdentity(c, state); err != nil {
		return err
	}
	e := &Engine{Config: c, State: state, StatePath: statePath, Apply: opts.apply, Runner: proc.Exec{}, Observer: discovery.New(c.Monitor), Log: log}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSeconds)*time.Second)
	defer cancel()
	switch operation {
	case "list":
		reg, err := e.loadDevices(ctx, a)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(reg.Devices, "", "  ")
		_, err = fmt.Fprintln(out, string(b))
		return err
	case "retire":
		return e.retireDevice(ctx, opts.action, a, id)
	}
	return e.enrollDevice(ctx, opts.action, a, operation == "activate")
}

// DeviceOperations are the operations of the devices command.
var DeviceOperations = []string{"list", "enroll", "retire", "activate"}

// devicesOperation returns the devices command's operation and the identity
// it acts on: this machine's, or retire's canonical USER@HOST argument.
func devicesOperation(f *cmdline.Line, c config.Config, positional []string) (operation, id string, err error) {
	if len(positional) == 0 {
		return "", "", f.Errorf("choose an operation: list, enroll, retire USER@HOST, or activate")
	}
	operation, rest := positional[0], positional[1:]
	id = c.Identity
	if !slices.Contains(DeviceOperations, operation) {
		return "", "", f.Errorf("unknown operation %q; use list, enroll, retire, or activate", operation)
	}
	if operation == "retire" {
		if len(rest) != 1 {
			return "", "", f.Errorf("retire needs exactly one USER@HOST")
		}
		if id, err = config.CanonicalIdentity(rest[0]); err != nil {
			return "", "", err
		}
		rest = nil
	}
	if len(rest) != 0 {
		return "", "", f.Errorf("unexpected arguments %q", rest)
	}
	return operation, id, nil
}

// devicesAction returns the device action that opts names, or the profile's
// only one, and sets opts.action to its name.
func devicesAction(f *cmdline.Line, c config.Config, opts *DevicesOptions) (config.ActionConfig, error) {
	if opts.action == "" {
		var names []string
		for _, name := range config.ActionNames(c) {
			if c.Actions[name].Devices != nil {
				names = append(names, name)
			}
		}
		if len(names) != 1 {
			return config.ActionConfig{}, f.Errorf("choose --action NAME: this profile has %d device actions", len(names))
		}
		opts.action = names[0]
	}
	a, ok := c.Actions[opts.action]
	if !ok || a.Devices == nil {
		return config.ActionConfig{}, f.Errorf("unknown device action %q", opts.action)
	}
	return a, nil
}

// enrollDevice enrolls this machine in device action name at its confirmed
// current address, after removing its retirement marker when activate is set.
// A retirement found in the cloud is cleaned up and then reported as
// errIdentityRetired, so enrolling a retired identity never exits 0.
func (e *Engine) enrollDevice(ctx context.Context, name string, a config.ActionConfig, activate bool) error {
	o := e.Observer.Observe(ctx, "")
	if !o.Verified {
		return fmt.Errorf("cannot confirm current IP: %w", o.Err)
	}
	e.State.IP = o.IP
	e.State.Connectivity = config.ConnectivityOnline
	if activate {
		if err := e.activateDevice(ctx, name, a); err != nil {
			return err
		}
		if !e.Apply {
			e.Log.Log("would_activate_identity", map[string]any{"identity": e.Config.Identity, "ip": o.IP})
			return nil
		}
	}
	if e.State.Action(name).Retired {
		return errIdentityRetired
	}
	if err := e.runDevices(ctx, name, a, o.IP, true); err != nil {
		return err
	}
	s := e.State.Action(name)
	s.AppliedIP = o.IP
	s.AppliedFingerprint = config.Fingerprint(a)
	s.LastSuccess = e.now()
	s.Pending = nil
	s.LastError = ""
	s.Attempts = 0
	return e.save()
}
