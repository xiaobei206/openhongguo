package sdk

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProfileGenerationIsRandomAndSecretFree(t *testing.T) {
	a, err := NewAnonymousDeviceProfile(nil, func() time.Time { return time.Unix(10, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAnonymousDeviceProfile(nil, func() time.Time { return time.Unix(10, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	if a.CDID == b.CDID || a.OpenUDID == b.OpenUDID {
		t.Fatal("profiles were not random")
	}
	if a.DeviceID != "" || a.InstallID != "" || a.DeviceToken != "" {
		t.Fatal("local profile invented a server identity")
	}
	if len(a.CDID) != 36 || a.CreatedAt.IsZero() {
		t.Fatalf("profile = %+v", a)
	}
}

func TestDeviceProfilePersistsKlinkEGDI(t *testing.T) {
	before := &DeviceProfile{DeviceID: "device-id", InstallID: "install-id", KlinkEGDI: "server-egdi-value"}
	encoded, err := json.Marshal(before)
	if err != nil { t.Fatal(err) }
	var after DeviceProfile
	if err := json.Unmarshal(encoded, &after); err != nil { t.Fatal(err) }
	if after.KlinkEGDI != before.KlinkEGDI {
		t.Fatalf("persisted KlinkEGDI = %q, want %q", after.KlinkEGDI, before.KlinkEGDI)
	}
}
