package sign

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPlaybackV5SignKeepsTheTicketSlot(t *testing.T) {
	s := NewPlaybackV5Signer(1_794_000_000_000)
	body := []byte("gzip bytes")
	query, headers, err := s.Sign([][2]string{{"a", "1"}, {"_rticket", ""}, {"device_id", "7100000000000001"}}, 1_794_000_000_123, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(query, "a=1&_rticket=") || !strings.HasSuffix(query, "&device_id=7100000000000001") || strings.Count(query, "_rticket=") != 1 {
		t.Fatalf("query = %s", query)
	}
	if headers["x-medusa"] == "" || headers["x-helios"] == "" || headers["x-ss-stub"] == "" {
		t.Fatalf("headers = %v", headers)
	}
	query, _, err = s.Sign([][2]string{{"a", "1"}, {"device_id", "7100000000000001"}}, 1_794_000_000_123, body, nil)
	if err != nil || !strings.HasPrefix(query, "a=1&device_id=7100000000000001&_rticket=") {
		t.Fatalf("appended ticket query = %s err %v", query, err)
	}
}

func TestPlaybackV5SignOmitsStubForBodylessRequest(t *testing.T) {
	s := NewPlaybackV5Signer(1_794_000_000_000)
	query, headers, err := s.Sign([][2]string{{"video_id", "7100000000000301"}}, 1_794_000_000_123, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, "video_id=7100000000000301") || !strings.Contains(query, "_rticket=") {
		t.Fatalf("query = %s", query)
	}
	if headers["x-khronos"] == "" || headers["x-helios"] == "" || headers["x-medusa"] == "" {
		t.Fatalf("headers = %v", headers)
	}
	if _, ok := headers["x-ss-stub"]; ok {
		t.Fatalf("bodyless request carried x-ss-stub: %v", headers)
	}
	if _, ok := headers["Content-Type"]; ok {
		t.Fatalf("bodyless request carried Content-Type: %v", headers)
	}
}

func TestPlaybackV5EmptyBodyUsesMD5OfEmptyBytes(t *testing.T) {
	s := NewPlaybackV5Signer(1_794_000_000_000)
	_, headers, err := s.Sign([][2]string{{"video_id", "123"}}, 1_794_000_000_123, []byte{}, nil)
	if err != nil { t.Fatal(err) }
	sum := md5.Sum([]byte{})
	if got, want := headers["x-ss-stub"], strings.ToUpper(hex.EncodeToString(sum[:])); got != want {
		t.Fatalf("empty-body x-ss-stub = %q, want MD5(empty) %q", got, want)
	}
	_, noBodyHeaders, err := s.Sign([][2]string{{"video_id", "123"}}, 1_794_000_000_123, nil, nil)
	if err != nil { t.Fatal(err) }
	if _, ok := noBodyHeaders["x-ss-stub"]; ok {
		t.Fatalf("nil body unexpectedly has x-ss-stub: %#v", noBodyHeaders)
	}
}

func TestPlaybackV5EmitsCompleteMobileHeaderSuite(t *testing.T) {
	s := NewPlaybackV5Signer(1_794_000_000_000)
	body := []byte("gzip bytes")
	_, headers, err := s.Sign([][2]string{
		{"device_id", "7100000000000001"},
		{"version_name", "7.4.3.32"},
		{"device_type", "24129PN74C"},
		{"device_brand", "Xiaomi"},
		{"os_version", "15"},
		{"channel", "xiaomi_8662_64"},
	}, 1_794_000_000_123, body, nil)
	if err != nil { t.Fatal(err) }
	for _, key := range []string{"x-khronos","x-gorgon","x-argus","x-ladon","x-helios","x-medusa"} {
		if headers[key] == "" { t.Errorf("missing V5 security header %q", key) }
	}
	if headers["x-xs-from-web"] != "0" { t.Fatalf("x-xs-from-web = %q", headers["x-xs-from-web"]) }
}
func TestPlaybackV5SecDeviceTokenIs25CharsAndPrefixed(t *testing.T) {
	token := playbackV5SecDeviceToken("abcdefghijklmnopqrstuvwx")
	if len(token) != 25 || token[0] != 'A' { t.Fatalf("sec_device_token = %q (len=%d)", token, len(token)) }
}
