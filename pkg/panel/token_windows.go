package panel

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The gecit data directory grants Builtin\Users read so an operator can open
// the log file, and that permission inherits onto everything created there. A
// token anyone can read hands config rewriting and engine control to any
// standard user, so the file carries its own protected ACL: SYSTEM and
// Administrators, nobody else.
const tokenSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// createTokenFile carries the ACL into CreateFile itself. os.OpenFile with 0600
// would create the file with the directory's inherited entries and only fix
// them afterwards, and a standard user spinning on the path reads the token in
// between. One win is permanent, so the window is not acceptable.
func createTokenFile(path string) (*os.File, error) {
	sd, err := windows.SecurityDescriptorFromString(tokenSDDL)
	if err != nil {
		return nil, fmt.Errorf("build ACL for %s: %w", path, err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))

	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(
		name,
		windows.GENERIC_WRITE,
		0,
		&sa,
		windows.CREATE_NEW,
		// Without this the create follows a junction planted at the path and
		// hands the token, and its ACL, to wherever that points.
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// secureToken asserts that ACL on a file that already exists, for the case
// where an older gecit created it before createTokenFile did. Go's permission
// bits only drive the read-only attribute on Windows, so a file created with
// 0600 still carries the directory's inherited entries.
func secureToken(path string) error {
	sd, err := windows.SecurityDescriptorFromString(tokenSDDL)
	if err != nil {
		return fmt.Errorf("build ACL for %s: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read ACL for %s: %w", path, err)
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("secure %s: %w", path, err)
	}
	return nil
}
