package cert

import (
	"os"
	"path"
	"testing"
)

func TestCertsRoundTrip(t *testing.T) {
	certs := []string{"single.crt"}
	for _, c := range certs {
		t.Run(c, func(t *testing.T) {
			in, err := os.ReadFile(path.Join("testdata", c))
			if err != nil {
				t.Fatalf("error reading file: %v", err)
			}
			parsed, err := bytesToCerts(in, 10)
			if err != nil {
				t.Fatalf("got error: %v", err)
			}

			certString := certsToString(parsed...)

			if string(in) != certString {
				t.Errorf("original %s, new %s", in, certString)
			}
		})
	}
}

func TestKeyRoundTrip(t *testing.T) {
	keys := []string{"ec256.key", "ed25519.key", "rsa2048.key"}
	for _, file := range keys {
		t.Run(file, func(t *testing.T) {
			in, err := os.ReadFile(path.Join("testdata", file))
			if err != nil {
				t.Fatalf("error reading file: %v", err)
			}
			parsed, err := bytesToKey(in)
			if err != nil {
				t.Fatalf("got error: %v", err)
			}

			keyString, err := keyToString(parsed)
			if err != nil {
				t.Fatalf("got error: %v", err)
			}

			if string(in) != keyString {
				t.Errorf("original %s, new %s", in, keyString)
			}
		})
	}
}

// Test that we can successfully read EC private keys and PKCS1 keys.
func TestBytesToKey(t *testing.T) {
	keys := []string{"ec_private_key.key", "pkcs1_rsa.key"}
	for _, file := range keys {
		t.Run(file, func(t *testing.T) {
			in, err := os.ReadFile(path.Join("testdata", file))
			if err != nil {
				t.Fatalf("error reading file: %v", err)
			}
			_, err = bytesToKey(in)
			if err != nil {
				t.Fatalf("got error: %v", err)
			}
		})
	}
}
