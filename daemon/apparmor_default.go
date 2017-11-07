// +build linux

package daemon

import (
	"fmt"

	aaprofile "github.com/docker/docker/profiles/apparmor"
	"github.com/opencontainers/runc/libcontainer/apparmor"
)

// Define constants for native driver
const (
	defaultApparmorProfile = "docker-default"
)

func ensureDefaultAppArmorProfile() error {
	if apparmor.IsEnabled() {
		//cyz-> 从kernel的/sys/kernel/security/apparmor/里读取，看看defaultApparmorProfile有没有被apparmor载入
		loaded, err := aaprofile.IsLoaded(defaultApparmorProfile)
		if err != nil {
			return fmt.Errorf("Could not check if %s AppArmor profile was loaded: %s", defaultApparmorProfile, err)
		}

		// Nothing to do.
		if loaded {
			return nil
		}

		// Load the profile.
		//cyz-> 将defaultApparmorProfile安装，aaprofile.InstallDefault generates a default profile in a temp directory determined by
		//cyz-> os.TempDir(), then loads the profile into the kernel using 'apparmor_parser'.
		//cyz-> 调用了"github.com/docker/docker/pkg/aaparser"，它对apparmor这个binary进行了简单封装。
		if err := aaprofile.InstallDefault(defaultApparmorProfile); err != nil {
			return fmt.Errorf("AppArmor enabled on system but the %s profile could not be loaded: %s", defaultApparmorProfile, err)
		}
	}

	return nil
}
