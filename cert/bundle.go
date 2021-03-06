package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"

	"software.sslmate.com/src/go-pkcs12"
)

const (
	caChainLimit = 11
)

type Bundle struct {
	Certificate *x509.Certificate
	CA          []*x509.Certificate
	PrivateKey  crypto.PrivateKey
}

func (cb *Bundle) CertString() string {
	return string(certsToString(cb.Certificate))
}

func (cb *Bundle) CAString() string {
	return string(certsToString(cb.CA...))
}

func (cb *Bundle) KeyString() (string, error) {
	return keyToString(cb.PrivateKey)
}

func BundleFromBytes(cert []byte, key []byte, ca []byte) (*Bundle, error) {
	cb := &Bundle{}

	var err error
	var parsed []*x509.Certificate
	if cert != nil {
		parsed, err = bytesToCerts(cert, 1)
		if err != nil {
			return nil, err
		}
		if len(parsed) == 0 {
			return nil, errors.New("got 0 certificates")
		}
		cb.Certificate = parsed[0]
	}

	if ca != nil {
		parsed, err = bytesToCerts(ca, caChainLimit)
		if err != nil {
			return nil, err
		}
		if len(parsed) == 0 {
			return nil, errors.New("got 0 issuer certificates")
		}
		cb.CA = parsed
	}

	if key != nil {
		cb.PrivateKey, err = bytesToKey(key)
		if err != nil {
			return nil, err
		}
	}

	return cb, nil
}

func (cb *Bundle) PFX() ([]byte, error) {
	return pkcs12.Encode(rand.Reader, cb.PrivateKey, cb.Certificate, cb.CA, "")
}
