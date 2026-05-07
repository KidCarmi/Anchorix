package inventory

import (
	"errors"
	"testing"
)

func TestRejectPrivateKeyMaterial(t *testing.T) {
	cases := []struct {
		name    string
		pem     string
		wantErr bool
	}{
		{"public cert only", "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n", false},
		{"rsa private key", "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n", true},
		{"pkcs8 private key", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", true},
		{"ec private key", "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----\n", true},
		{"encrypted private key", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc\n-----END ENCRYPTED PRIVATE KEY-----\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectPrivateKeyMaterial(InventoryBatch{
				Certificates: []DiscoveredCertificate{{CertificatePEM: tc.pem}},
			})
			if tc.wantErr && !errors.Is(err, ErrPrivateKeyMaterial) {
				t.Fatalf("want ErrPrivateKeyMaterial, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want no error, got %v", err)
			}
		})
	}
}
