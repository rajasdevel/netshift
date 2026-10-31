//go:build windows

package engine

import (
	"encoding/base64"
	"time"
	"unicode/utf16"
)

// notifyTimeout bounds one notification helper. Windows PowerShell can take
// several seconds to start.
const notifyTimeout = 20 * time.Second

// ToastProgram shows Windows notifications; every Windows installation has
// it.
const ToastProgram = "powershell.exe"

// toastScript shows a Windows toast with the title and body it reads from
// the environment. It is a constant: the text reaches it only as data, as
// text nodes it never parses, so nothing in it can be read as code or XML.
// Toasts need an app ID that Windows knows; Windows PowerShell's is
// registered on every installation.
const toastScript = `$ErrorActionPreference = 'Stop'
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$toast = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$lines = $toast.GetElementsByTagName('text')
$null = $lines.Item(0).AppendChild($toast.CreateTextNode($env:NETSHIFT_NOTIFY_TITLE))
$null = $lines.Item(1).AppendChild($toast.CreateTextNode($env:NETSHIFT_NOTIFY_BODY))
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($toast))
`

// toastCommand returns the Windows PowerShell command that shows a toast. The title and body are passed only as environment values, which
// toastScript reads as data. -EncodedCommand takes the script as Base64
// UTF-16, so no quoting rules of the command line or of PowerShell apply.
func toastCommand(title, body string) (program string, args, env []string) {
	units := utf16.Encode([]rune(toastScript))
	script := make([]byte, 0, 2*len(units))
	for _, u := range units {
		script = append(script, byte(u), byte(u>>8))
	}
	args = []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", base64.StdEncoding.EncodeToString(script)}
	return ToastProgram, args, []string{"NETSHIFT_NOTIFY_TITLE=" + title, "NETSHIFT_NOTIFY_BODY=" + body}
}
