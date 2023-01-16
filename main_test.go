package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/devon-mar/acmevault/cert"
	"github.com/devon-mar/acmevault/store"
)

func TestShouldRenew(t *testing.T) {
	now := time.Now()
	testCases := map[string]struct {
		want      bool
		notBefore time.Time
		notAfter  time.Time
	}{
		"expired": {
			want:      true,
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(-1 * time.Hour),
		},
		"future": {
			want:      false,
			notBefore: now.Add(1 * time.Hour),
			notAfter:  now.Add(24 * time.Hour),
		},
		"past 2/3": {
			want:      true,
			notBefore: now.Add(-17 * time.Hour),
			notAfter:  now.Add(7 * time.Hour),
		},
		"before 2/3": {
			want:      false,
			notBefore: now.Add(-7 * time.Hour),
			notAfter:  now.Add(17 * time.Hour),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			template := x509.Certificate{
				SerialNumber: big.NewInt(123),
				NotBefore:    tc.notBefore,
				NotAfter:     tc.notAfter,
			}

			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("error generating key: %v", err)
			}
			pubKey := priv.PublicKey

			b, err := x509.CreateCertificate(rand.Reader, &template, &template, &pubKey, priv)
			if err != nil {
				t.Fatalf("error generating cert: %v", err)
			}

			cert, err := x509.ParseCertificate(b)
			if err != nil {
				t.Fatalf("error parsing DER: %v", err)
			}

			if have := shouldRenew(cert, now); have != tc.want {
				t.Errorf("got %t, wanted %t", have, tc.want)
			}
		})
	}
}

type testStore struct {
	account            map[string]string
	retrieveAccountErr error
	storedAccount      map[string]string
	storeAccountErr    error

	stored []string

	wantAccount map[string]string
	wantStored  []string

	storePath string
}

// Retrieve implements store.Store
func (s *testStore) Retrieve(cn string) (*cert.Bundle, error) {
	storePath := s.storePath
	if storePath == "" {
		storePath = "testdata/store"
	}
	certPath := path.Join(storePath, cn+".crt")
	keyPath := path.Join(storePath, cn+".key")
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if certErr == nil && keyErr == nil {
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("error reading cert: %v", err)
		}
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("error reading key: %v", err)
		}
		return cert.BundleFromBytes(certBytes, keyBytes, nil)
	}
	return nil, nil
}

// RetrieveAccount implements store.Store
func (s *testStore) RetrieveAccount() (map[string]string, error) {
	return s.account, s.retrieveAccountErr
}

// Store implements store.Store
func (s *testStore) Store(cb *cert.Bundle) error {
	cn := cb.Certificate.Subject.CommonName
	if cn == "storeerror.example.com" {
		return errors.New("got store error cert")
	}
	s.stored = append(s.stored, cb.Certificate.Subject.CommonName)
	return nil
}

// StoreAccount implements store.Store
func (s *testStore) StoreAccount(acc map[string]string) error {
	s.storedAccount = acc
	return s.storeAccountErr
}

func (s *testStore) assert(t *testing.T) {
	if !reflect.DeepEqual(s.storedAccount, s.wantAccount) {
		t.Errorf("expected %#v to be stored but got %#v", s.wantAccount, s.storedAccount)
	}
	if !reflect.DeepEqual(s.stored, s.wantStored) {
		t.Errorf("stored: got %#v, want %#v", s.stored, s.wantStored)
	}
}

type testIssuer struct {
	issuedCerts int
	wantIssued  int

	mustHaveKey bool
}

// Issue implements cert.Issuer
func (ti *testIssuer) Issue(req cert.CertRequest) (*cert.Bundle, error) {
	if req.PrivateKey == nil && ti.mustHaveKey {
		return nil, errors.New("private key is required")
	} else if req.PrivateKey != nil && !ti.mustHaveKey {
		return nil, errors.New("no private key expected")
	}

	f, err := os.ReadFile(path.Join("testdata/issue", req.Domains[0]+".crt"))
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	ti.issuedCerts++
	return cert.BundleFromBytes(f, nil, nil)
}

func (ti *testIssuer) assert(t *testing.T) {
	t.Helper()
	if ti.issuedCerts != ti.wantIssued {
		t.Errorf("expected %d certs to be issued but got %d", ti.wantIssued, ti.issuedCerts)
	}
}

func simpleCC(domains ...string) certConfig {
	return certConfig{
		CertRequest: cert.CertRequest{Domains: domains},
	}
}

func newSelfSigned(cn string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key: %v", err)
	}
	pubKey := priv.PublicKey

	template := x509.Certificate{
		Subject:      pkix.Name{CommonName: cn},
		SerialNumber: big.NewInt(123),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	b, err := x509.CreateCertificate(rand.Reader, &template, &template, &pubKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshalling private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

func TestRun(t *testing.T) {
	// Generate a self signed certificate
	certDir := t.TempDir()
	cn := "donotrenew.example.com"
	pub, priv, err := newSelfSigned(cn)
	if err != nil {
		t.Fatalf("error generating self signed: %v", err)
	}

	if err := os.WriteFile(path.Join(certDir, cn+".crt"), pub, 0o600); err != nil {
		t.Fatalf("error writing cert: %v", err)
	}
	if err := os.WriteFile(path.Join(certDir, cn+".key"), priv, 0o600); err != nil {
		t.Fatalf("error writing key: %v", err)
	}

	testAcc1 := map[string]string{"name": "testacc1", "type": "test account"}
	tests := map[string]struct {
		config         *config
		accountToStore map[string]string
		store          *testStore
		storeError     error
		issuer         *testIssuer
		issuerError    error
		reuseKey       bool
		wantReturn     int
	}{
		"issue 1, no account in store, reuseKey=f": {
			config: &config{certs: []certConfig{simpleCC("expired.example.com")}},
			store: &testStore{
				wantAccount: testAcc1,
				wantStored:  []string{"expired.example.com"},
			},
			accountToStore: testAcc1,
			issuer:         &testIssuer{wantIssued: 1},
		},
		"issue 1,reuseKey=t": {
			config: &config{certs: []certConfig{
				{CertRequest: cert.CertRequest{Domains: []string{"expired.example.com"}}, reuseKey: true},
			}},
			store: &testStore{
				account:    testAcc1,
				wantStored: []string{"expired.example.com"},
			},
			issuer: &testIssuer{
				mustHaveKey: true,
				wantIssued:  1,
			},
		},
		"1 not expired": {
			config: &config{certs: []certConfig{
				{CertRequest: cert.CertRequest{Domains: []string{"donotrenew.example.com"}}, reuseKey: true},
			}},
			store:  &testStore{account: testAcc1, storePath: certDir},
			issuer: &testIssuer{},
		},
		"store error": {
			config:         &config{certs: []certConfig{simpleCC("storeerror.example.com")}},
			store:          &testStore{wantAccount: testAcc1},
			issuer:         &testIssuer{wantIssued: 1},
			wantReturn:     1,
			accountToStore: testAcc1,
		},
		"1 issue error": {
			config:     &config{certs: []certConfig{simpleCC("error.example.com")}},
			store:      &testStore{account: testAcc1},
			issuer:     &testIssuer{},
			wantReturn: 1,
		},
		"store retrieve error": {
			// we'll just give it a bad PEM file to trigger an error
			config:     &config{certs: []certConfig{simpleCC("invalid")}},
			store:      &testStore{account: testAcc1},
			issuer:     &testIssuer{},
			wantReturn: 1,
		},
		"2 issue errors": {
			config:     &config{certs: []certConfig{simpleCC("error.example.com"), simpleCC("error2.example.com")}},
			store:      &testStore{account: testAcc1},
			issuer:     &testIssuer{},
			wantReturn: 2,
		},
		"2 issue errors, exitOnError": {
			config: &config{
				certs:       []certConfig{simpleCC("error.example.com"), simpleCC("error2.example.com")},
				exitOnError: true,
			},
			store:      &testStore{account: testAcc1},
			issuer:     &testIssuer{},
			wantReturn: 1,
		},
		// StoreAccount shouldn't be called
		"account already in store": {
			config: &config{certs: []certConfig{}},
			store:  &testStore{account: testAcc1},
			issuer: &testIssuer{},
		},
		"store account err": {
			config:         &config{certs: []certConfig{}},
			store:          &testStore{storeAccountErr: errors.New("test"), wantAccount: testAcc1},
			accountToStore: testAcc1,
			issuer:         &testIssuer{},
			wantReturn:     1,
		},
		"RetrieveAccount error": {
			config:     &config{certs: []certConfig{}},
			store:      &testStore{retrieveAccountErr: errors.New("test error")},
			wantReturn: 1,
		},
		"issuer init error": {
			config:      &config{},
			store:       &testStore{account: testAcc1},
			issuerError: errors.New("test error"),
			wantReturn:  1,
		},
		"store init error": {
			config:     &config{},
			storeError: errors.New("test"),
			wantReturn: 1,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			have := run(
				tc.config,
				func() (store.Store, error) { return tc.store, tc.storeError },
				func(m map[string]string) (cert.Issuer, map[string]string, error) {
					return tc.issuer, tc.accountToStore, tc.issuerError
				},
			)
			if have != tc.wantReturn {
				t.Errorf("expected return code %d, got %d", tc.wantReturn, have)
			}

			if tc.issuer != nil {
				tc.issuer.assert(t)
			}
			if tc.store != nil {
				tc.store.assert(t)
			}
		})
	}
}
