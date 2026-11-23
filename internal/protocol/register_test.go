package protocol

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/beilunyang/openhongguo/sdk/model"
)

func TestParseRegisterKeepsOptionalKlinkEGDI(t *testing.T) {
	got, err := ParseRegister([]byte(`{"device_id_str":"7100000000000001","install_id_str":"7200000000000002","klink_egdi":"server-egdi-value"}`))
	if err != nil { t.Fatal(err) }
	if got.KlinkEGDI != "server-egdi-value" { t.Fatalf("KlinkEGDI = %q", got.KlinkEGDI) }
}

func TestParseRegisterAcceptsEGDIAlternateAndMissingToken(t *testing.T) {
	withAlias, err := ParseRegister([]byte(`{"device_id_str":"7100000000000001","install_id_str":"7200000000000002","egdi":"alias-value"}`))
	if err != nil { t.Fatal(err) }
	if withAlias.KlinkEGDI != "alias-value" { t.Fatalf("KlinkEGDI alias = %q", withAlias.KlinkEGDI) }
	without, err := ParseRegister([]byte(`{"device_id_str":"7100000000000001","install_id_str":"7200000000000002"}`))
	if err != nil { t.Fatal(err) }
	if without.KlinkEGDI != "" { t.Fatalf("missing KlinkEGDI = %q", without.KlinkEGDI) }
}

func decryptRegisterTestEnvelope(t *testing.T, body []byte) []byte {
	t.Helper()
	prefix := []byte{0x74, 0x63, 0x05, 0x10, 0x00, 0x00}
	if len(body) < len(prefix)+len(ttEncryptPrefix)+aes.BlockSize ||
		!bytes.Equal(body[:len(prefix)], prefix) ||
		!bytes.Equal(body[len(prefix):len(prefix)+len(ttEncryptPrefix)], ttEncryptPrefix) {
		t.Fatalf("unexpected tt-data registration envelope")
	}
	ciphertext := body[len(prefix)+len(ttEncryptPrefix):]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		t.Fatalf("invalid registration ciphertext length %d", len(ciphertext))
	}
	prefixHash := sha512.Sum512(ttEncryptPrefix)
	material := append(append([]byte(nil), prefixHash[:]...), ttEncryptConstant...)
	keyIV := sha512.Sum512(material)
	block, err := aes.NewCipher(keyIV[:16])
	if err != nil { t.Fatal(err) }
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, keyIV[16:32]).CryptBlocks(plain, ciphertext)
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plain) {
		t.Fatalf("invalid registration padding: %d", padding)
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding { t.Fatal("invalid registration padding bytes") }
	}
	plain = plain[:len(plain)-padding]
	if len(plain) < sha512.Size { t.Fatal("registration envelope has no digest") }
	compressed := plain[sha512.Size:]
	wantDigest := sha512.Sum512(compressed)
	if !bytes.Equal(plain[:sha512.Size], wantDigest[:]) {
		t.Fatal("registration envelope digest mismatch")
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil { t.Fatal(err) }
	defer zr.Close()
	payload, err := io.ReadAll(zr)
	if err != nil { t.Fatal(err) }
	return payload
}

func oaIDValue(value map[string]any) string {
	id, _ := value["id"].(string)
	return id
}

func TestBuildHeartbeatBodyPreservesExistingDeviceIdentity(t *testing.T) {
	profile := RegisterIdentity{
		CDID: "cdid-existing",
		OpenUDID: "openudid-existing",
		ClientUDID: "clientudid-existing",
		OAID: "oaid-existing",
		ReqID: "req-existing",
		Device: model.DefaultDevice,
	}
	body, err := BuildHeartbeatBody(profile, "device-existing", "install-existing", time.UnixMilli(1_800_000_000_123))
	if err != nil { t.Fatal(err) }
	payload := decryptRegisterTestEnvelope(t, body)
	var decoded struct {
		Header map[string]any `json:"header"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil { t.Fatal(err) }
	want := map[string]string{
		"device_id": "device-existing",
		"install_id": "install-existing",
		"cdid": "cdid-existing",
		"openudid": "openudid-existing",
		"clientudid": "clientudid-existing",
		"req_id": "req-existing",
	}
	for key, value := range want {
		if got, _ := decoded.Header[key].(string); got != value {
			t.Errorf("heartbeat header %s = %q, want %q", key, got, value)
		}
	}
	oaid, ok := decoded.Header["oaid"].(map[string]any)
	if !ok || oaIDValue(oaid) != "oaid-existing" {
		t.Errorf("heartbeat OAID object = %#v, want id=%q", decoded.Header["oaid"], "oaid-existing")
	}
}

func TestBuildHeartbeatBodyRejectsMissingExistingIDs(t *testing.T) {
	profile := RegisterIdentity{CDID:"cdid", OpenUDID:"open", ClientUDID:"client", Device:model.DefaultDevice}
	if _, err := BuildHeartbeatBody(profile, "", "install-existing", time.Now()); err == nil {
		t.Fatal("heartbeat accepted empty device_id")
	}
	if _, err := BuildHeartbeatBody(profile, "device-existing", "0", time.Now()); err == nil {
		t.Fatal("heartbeat accepted zero install_id")
	}
}
