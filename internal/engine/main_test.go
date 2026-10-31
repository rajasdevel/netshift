package engine

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// fakeAzureEnv names a directory of NSG documents. When it is set, the test
// binary acts as an Azure CLI that prints the one named by --name.
const fakeAzureEnv = "NETSHIFT_FAKE_AZURE_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(fakeAzureEnv); dir != "" {
		args := os.Args[1:]
		i := slices.Index(args, "--name")
		if i < 0 || i+1 == len(args) {
			os.Exit(1)
		}
		data, err := os.ReadFile(filepath.Join(dir, args[i+1]+".json"))
		if err != nil {
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	}
	os.Exit(m.Run())
}
