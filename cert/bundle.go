package cert

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/devon-mar/pkiutil"
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
	b, err := pkiutil.MarshalPrivateKey(cb.PrivateKey)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func BundleFromBytes(cert []byte, key []byte, ca [][]byte) (*Bundle, error) {
	cb := &Bundle{}

	var err error
	if cert != nil {
		cb.Certificate, err = pkiutil.ParseCertificate(cert)
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
	}

	cb.CA = make([]*x509.Certificate, len(ca))
	for i, rawCa := range ca {
		cb.CA[i], err = pkiutil.ParseCertificate(rawCa)
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
	}

	if key != nil {
		cb.PrivateKey, err = pkiutil.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
	}

	return cb, nil
}

func (cb *Bundle) PFX() ([]byte, error) {
	return pkcs12.Legacy.Encode(cb.PrivateKey, cb.Certificate, cb.CA, "")
}
