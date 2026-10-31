//go:build windows

package doctor

import (
	"context"

	"github.com/rajasdevel/netshift/internal/engine"
	"github.com/rajasdevel/netshift/internal/proc"
	"github.com/rajasdevel/netshift/internal/service"
)

// toastHelper returns the program that shows desktop notifications.
func toastHelper() string { return engine.ToastProgram }

// taskServiceState asks Task Scheduler whether a Windows task is
// registered, enabled, and running.
func taskServiceState(ctx context.Context, runner proc.Runner, s service.Spec) (string, string, bool) {
	if s.Platform != "windows" {
		return "", "", false
	}
	task, err := service.QueryTask(ctx, runner, s)
	switch {
	case err != nil:
		return serviceFailed, "Task Scheduler did not report the task: " + err.Error(), true
	case task.Running:
		return serviceRunning, "", true
	case !task.Registered:
		return serviceFailed, "the task definition exists but no task is registered; run service install", true
	case !task.Enabled:
		return serviceStopped, "", true // as install leaves it without --start
	}
	return serviceFailed, "installed and enabled but not running", true
}
