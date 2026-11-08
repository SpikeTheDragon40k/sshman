//go:build windows

package vault

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// New vault, backup and lock files get a protected owner-only DACL.
func TestWindowsNewFilesAreOwnerOnly(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("pw-win"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, pw("pw-win"), sampleEntries()); err != nil { // creates .bak
		t.Fatal(err)
	}
	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, BackupPath(path), lockPath(path)} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		ctl, _, _ := sd.Control()
		if ctl&windows.SE_DACL_PROTECTED == 0 {
			t.Errorf("%s: DACL not protected (inherits)", p)
		}
		dacl, _, _ := sd.DACL()
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			_ = windows.GetAce(dacl, i, &ace)
			sid := (*windows.SID)(unsafePointer(&ace.SidStart))
			if !sid.Equals(user) && !sid.IsWellKnown(windows.WinLocalSystemSid) {
				t.Errorf("%s: unexpected ACE for %s", p, sidName(sid))
			}
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkOpenFile(f, p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		f.Close()
	}
}

// S-10 on Windows: a vault readable or writable by other accounts is refused.
func TestWindowsInsecureACLRefused(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("pw-win-acl"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	user, _ := currentUserSID()
	for name, extra := range map[string]string{
		"Everyone read":            "(A;;FR;;;WD)",
		"Users write":              "(A;;FW;;;BU)",
		"Authenticated Users full": "(A;;FA;;;AU)",
	} {
		setDACL(t, path, "D:P(A;;FA;;;"+user.String()+")"+extra)
		if _, err := Load(path, pw("pw-win-acl")); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s: want ErrUnsafe, got %v", name, err)
		}
	}
	// A deny entry for others is fine; Administrators and SYSTEM are trusted.
	setDACL(t, path, "D:P(D;;FA;;;WD)(A;;FA;;;"+user.String()+")(A;;FA;;;SY)(A;;FA;;;BA)")
	if _, err := Load(path, pw("pw-win-acl")); err != nil {
		t.Fatalf("owner/SYSTEM/Administrators ACL refused: %v", err)
	}
}

func unsafePointer(p *uint32) unsafe.Pointer { return unsafe.Pointer(p) }
