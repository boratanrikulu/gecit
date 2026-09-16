package app

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SYSTEM and Administrators get full control, everyone else read and execute.
// P blocks inheritance from ProgramData, whose default ACL lets any user add
// subdirectories and own what they create. Without this a standard user could
// hand a LocalSystem service its own config.
const dataDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

func createDataDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return fmt.Errorf("build ACL for %s: %w", dir, err)
	}

	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", parent, err)
		}
	}

	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))

	err = windows.CreateDirectory(path, &sa)
	if err == nil {
		return nil
	}
	if err != windows.ERROR_ALREADY_EXISTS {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	// Someone got here first. Reassert the ACL rather than trusting whatever
	// they left, since they may still own the directory.
	return applyDataDirACL(dir, sd)
}

func applyDataDirACL(dir string, sd *windows.SECURITY_DESCRIPTOR) error {
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read ACL for %s: %w", dir, err)
	}
	err = windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("secure %s: %w", dir, err)
	}
	return nil
}
