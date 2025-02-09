package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

const (
	pemBlockCert = "CERTIFICATE"
)

func certsToString(certs ...*x509.Certificate) string {
	ret := []string{}
	for _, c := range certs {
		ret = append(ret, string(pem.EncodeToMemory(&pem.Block{Type: pemBlockCert, Bytes: c.Raw})))
	}
	return strings.Join(ret, "")
}

func readEnv(name string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return val, nil
}
