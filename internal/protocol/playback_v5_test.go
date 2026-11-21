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
		"channel":     device.Channel,
		"device_type": device.Model,
		"os_version":  device.OSVersion,
	} {
		if got[key] != want {
			t.Errorf("VideoTabPairs[%q] = %q, want %q", key, got[key], want)
		}
	}
	if device.Brand != "Xiaomi" || device.Model != "24129PN74C" || device.OSVersion != "15" || device.OSAPI != 35 {
		t.Fatalf("SDK default device is not the configured Xiaomi 15: %+v", device)
	}
}
