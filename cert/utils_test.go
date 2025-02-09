package cert

import (
	"os"
	"path"
	"testing"

	"github.com/devon-mar/pkiutil"
)

func TestCertsRoundTrip(t *testing.T) {
	certs := []string{"single.crt", "lets-encrypt-chain.pem"}
	for _, c := range certs {
		t.Run(c, func(t *testing.T) {
			in, err := os.ReadFile(path.Join("testdata", c))
			if err != nil {
				t.Fatalf("error reading file: %v", err)
			}
			parsed, err := pkiutil.ParseCertificates(in, 10)
			if err != nil {
				t.Fatalf("got error: %v", err)
			}

			certString := certsToString(parsed...)

			if string(in) != certString {
				t.Errorf("expected %q, got %q", in, certString)
			}
		})
	}
}
