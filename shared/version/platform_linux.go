//go:build linux

package version

import (
	"os"
	"strings"

	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/osarch"
)

func getPlatformVersionStrings() []string {
	versions := []string{}

	// Add kernel version
	uname, err := shared.Uname()
	if err != nil {
		return versions
	}

	versions = append(versions, strings.Split(uname.Release, "-")[0])

	// Add distribution info
	lsbRelease, err := osarch.GetLSBRelease()
	if err == nil {
		for _, key := range []string{"NAME", "VERSION_ID"} {
			value, ok := lsbRelease[key]
			if ok {
				versions = append(versions, value)
			}
		}
	}

	// Add chromebook info
	if len(versions) == 1 && shared.PathExists("/run/cros_milestone") {
		content, err := os.ReadFile("/run/cros_milestone")
		if err == nil {
			versions = append(versions, "Chrome OS", strings.TrimSpace(string(content)))
		}
	}

	return versions
}
