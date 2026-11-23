package protocol

import "testing"

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
