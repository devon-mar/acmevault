package cert

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

const (
	pemBlockCert         = "CERTIFICATE"
	pemBlockPrivateKey1  = "RSA PRIVATE KEY"
	pemBlockPrivateKey8  = "PRIVATE KEY"
	pemBlockECPrivateKey = "EC PRIVATE KEY"
)

func bytesToKey(b []byte) (crypto.PrivateKey, error) {
	decoded, _ := pem.Decode(b)
	if decoded == nil {
		return nil, fmt.Errorf("no PEM data found")
	}

	var c crypto.PrivateKey
	var err error

	switch decoded.Type {
	case pemBlockPrivateKey1:
		c, err = x509.ParsePKCS1PrivateKey(decoded.Bytes)
	case pemBlockECPrivateKey:
		c, err = x509.ParseECPrivateKey(decoded.Bytes)
	case pemBlockPrivateKey8:
		c, err = x509.ParsePKCS8PrivateKey(decoded.Bytes)
	default:
		return nil, fmt.Errorf("got unexpected block type %q for private key", decoded.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}
	return c, nil
}

func keyToString(k crypto.PrivateKey) (string, error) {
	var keyBytes []byte
	var err error

	keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPrivateKey8, Bytes: keyBytes})), nil
}

func bytesToCerts(b []byte, limit int) ([]*x509.Certificate, error) {
	rest := b

	ret := []*x509.Certificate{}

	for i := 0; i < limit; i++ {
		var decoded *pem.Block
		decoded, rest = pem.Decode(rest)
		if decoded == nil {
			break
		} else if decoded.Type != pemBlockCert {
			return nil, fmt.Errorf("got unexpected block type %q for public key", decoded.Type)
		}
		c, err := x509.ParseCertificate(decoded.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %w", err)
		}
		ret = append(ret, c)
	}

	return ret, nil
}

func certsToString(certs ...*x509.Certificate) string {
	ret := []string{}
	for _, c := range certs {
		ret = append(ret, string(pem.EncodeToMemory(&pem.Block{Type: pemBlockCert, Bytes: c.Raw})))
	}
	return strings.Join(ret, "\n")
}

func readEnv(name string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return val, nil
}
