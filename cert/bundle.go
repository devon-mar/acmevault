package cert

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

type Bundle struct {
	Certificate *x509.Certificate
	CA          []*x509.Certificate
	PrivateKey  crypto.PrivateKey
}

func (cb *Bundle) CertString() string {
	return string(certsToString(cb.Certificate))
}

func (cb *Bundle) ChainString() string {
	certs := []*x509.Certificate{cb.Certificate}
	certs = append(certs, cb.CA...)
	return string(certsToString(certs...))
}

func (cb *Bundle) CAStrings() []string {
	strs := make([]string, len(cb.CA))
	for i, ca := range cb.CA {
		strs[i] = certsToString(ca)
	}
	return strs
}

func (cb *Bundle) KeyString() (string, error) {
	return keyToString(cb.PrivateKey)
}

func BundleFromBytes(cert []byte, key []byte, ca [][]byte) (*Bundle, error) {
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

	cb.CA = make([]*x509.Certificate, len(ca))
	for i, rawCa := range ca {
		parsed, err = bytesToCerts(rawCa, 1)
		if err != nil {
			return nil, err
		}
		if len(parsed) == 0 {
			return nil, fmt.Errorf("no ca at %d", i)
		}
		cb.CA[i] = parsed[0]
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
	return pkcs12.Legacy.Encode(cb.PrivateKey, cb.Certificate, cb.CA, "")
}
