package protocol

import (
	"testing"

	"github.com/beilunyang/openhongguo/sdk/model"
)

func TestVideoTabPairsUseIdentityDevice(t *testing.T) {
	device := model.DefaultDevice
	id := SearchIdentity{
		DeviceID:  "device-id",
		InstallID: "install-id",
		CDID:      "cdid",
		Device:    device,
	}
	got := make(map[string]string)
	for _, pair := range VideoTabPairs("episode-id", id) {
		got[pair[0]] = pair[1]
	}
	for key, want := range map[string]string{
		"channel":      "vivo_8662_64",
		"device_type":  "PGT-AN10",
		"os_version":   "12",
		"version_code": "74532",
		"version_name": "7.4.5.32",
	} {
		if got[key] != want {
			t.Errorf("VideoTabPairs[%q] = %q, want %q", key, got[key], want)
		}
	}
	if device.Brand != "Xiaomi" || device.Model != "24129PN74C" || device.OSVersion != "15" || device.OSAPI != 35 {
		t.Fatalf("SDK default device is not the configured Xiaomi 15: %+v", device)
	}
	if got["iid"] != id.InstallID || got["cdid"] != id.CDID || got["device_id"] != id.DeviceID {
		t.Fatalf("VideoTabPairs lost persisted anonymous identity: %#v", got)
	}
}
