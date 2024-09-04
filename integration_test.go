//go:build integration

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devon-mar/acmevault/cert"
	"github.com/devon-mar/acmevault/store"

	vault "github.com/hashicorp/vault/api"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	testVaultToken = "4840549d-6897-4ab1-a414-2a971ff8bdde"
	testKVMount    = "secret"

	keyTypeRSA   = "RSA"
	keyTypeECDSA = "ECDSA"

	composeProjectName = "avtest"

	testCertDir    = "testdata/docker/certs"
	testServerCert = "server.crt"
	testServerKey  = "server.key"
	testClientCert = "client.crt"
	testClientKey  = "client.key"

	vaultAddr          = "https://localhost:8200"
	vaultCertAuthMount = "cert"
	vaultAccountPath   = "acme_account"
)

var defaultEnv = map[string]string{
	"LEGO_CA_CERTIFICATES":                 path.Join("testdata", "pebble_root.pem"),
	vault.EnvVaultAddress:                  vaultAddr,
	store.EnvVaultKVMount:                  testKVMount,
	store.EnvVaultKVCertsPath:              "certs",
	store.EnvVaultKVAccountPath:            vaultAccountPath,
	vault.EnvVaultCACert:                   path.Join(testCertDir, testServerCert),
	store.EnvVaultCertAuth:                 vaultCertAuthMount,
	vault.EnvVaultClientCert:               path.Join(testCertDir, testClientCert),
	vault.EnvVaultClientKey:                path.Join(testCertDir, testClientKey),
	cert.EnvACMEDir:                        "https://localhost:14000/dir",
	cert.EnvACMEEmail:                      "user@example.com",
	cert.EnvACMEDNSResolvers:               "127.0.0.1:1053",
	cert.EnvACMEDisableCompletePropagation: "true",
	cert.EnvACMEDNSProvider:                "temptxt",
	cert.EnvTTURL:                          "https://localhost:8443/update",
	cert.EnvTTCA:                           path.Join(testCertDir, testServerCert),
	cert.EnvTTCert:                         path.Join(testCertDir, testClientCert),
	cert.EnvTTKey:                          path.Join(testCertDir, testClientKey),
	cert.EnvACMETOSAgreed:                  "true",
}

func mustAbsolute(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		panic(err)
	}
	return abs
}

func TestMain(t *testing.T) {
	vaultCleanup, err := generateCerts()
	if err != nil {
		t.Fatalf("error generating vault certs: %v", err)
	}

	if err := dockerUp(); err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	t.Cleanup(dockerCleanup)

	// Remove certs after cleaning up containers.
	t.Cleanup(vaultCleanup)

	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = vaultAddr
	vaultCfg.ConfigureTLS(&vault.TLSConfig{Insecure: true})
	v, err := vault.NewClient(vaultCfg)
	if err != nil {
		t.Fatalf("error creating vault client")
	}
	v.SetToken(testVaultToken)

	tests := map[string]struct {
		env        map[string]string
		noCertAuth bool
		forceRenew bool

		wantStatus int

		assertions []assertOptions
	}{
		"rsa2048": {
			env: merge(defaultEnv, map[string]string{
				envCerts: "rsa2048.example.com",
			}),
			assertions: []assertOptions{
				{
					domains: []string{"rsa2048.example.com"},
					keyType: keyTypeRSA,
					keyLen:  2048,
				},
			},
		},
		"multiple, reuse": {
			env: merge(defaultEnv, map[string]string{
				envCerts: fmt.Sprintf("rsa2048.example.com\nrsa2048reuse.example.com,%s=true", certOptionReuseKey),
			}),
			assertions: []assertOptions{
				{
					domains: []string{"rsa2048.example.com"},
					keyType: keyTypeRSA,
					keyLen:  2048,
				},
				{
					domains:        []string{"rsa2048reuse.example.com"},
					keyType:        keyTypeRSA,
					keyLen:         2048,
					shouldReuseKey: true,
				},
			},
		},
		"ec256": {
			env: merge(defaultEnv, map[string]string{
				envCerts: fmt.Sprintf("ec256.example.com,ec256-1.example.com,%s=EC256", certOptionKeyType),
			}),
			assertions: []assertOptions{
				{
					domains: []string{"ec256.example.com", "ec256-1.example.com"},
					keyType: keyTypeECDSA,
					keyLen:  256,
				},
			},
		},
		"vault token auth": {
			env: merge(defaultEnv, map[string]string{
				envCerts:      "rsa2048.example.com",
				"VAULT_TOKEN": testVaultToken,
			}),
			noCertAuth: true,
			assertions: []assertOptions{
				{
					domains: []string{"rsa2048.example.com"},
					keyType: keyTypeRSA,
					keyLen:  2048,
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := dockerRestart(); err != nil {
				t.Fatalf("error starting containers: %v", err)
			}

			containerHealthCheck(t)

			if !tc.noCertAuth {
				err := configureVaultCertAuth(v)
				if err != nil {
					t.Fatalf("error configuring vault cert auth: %v", err)
				}
			}

			oldExitFunc := exitFunc
			defer func() { exitFunc = oldExitFunc }()

			t.Cleanup(setEnv(tc.env))

			// Test initial cert
			t.Log("Testing initial...")
			testShouldRenew = false
			defer func() { testShouldRenew = false }()

			haveStatus := -1
			exitFunc = func(s int) { haveStatus = s }

			main()

			if haveStatus != tc.wantStatus {
				t.Errorf("got status %d, want %d", haveStatus, tc.wantStatus)
			}
			for _, a := range tc.assertions {
				a.assert(t, v, 1)
			}

			// Test that the certificate isn't renewed when it doesn't need to be.
			t.Log("Testing idempotence...")
			main()
			if haveStatus != tc.wantStatus {
				t.Errorf("got status %d, want %d", haveStatus, tc.wantStatus)
			}
			for _, a := range tc.assertions {
				a.assert(t, v, 1)
			}
			assertAccountUnchanged(t, v)

			// Test renewal
			t.Log("Testing renewal...")
			haveStatus = -1
			testShouldRenew = true

			main()
			if haveStatus != tc.wantStatus {
				t.Errorf("got status %d, want %d", haveStatus, tc.wantStatus)
			}
			assertAccountUnchanged(t, v)
			for _, a := range tc.assertions {
				a.assert(t, v, 2)
			}
		})
	}
}

func setEnv(env map[string]string) func() {
	toRestore := map[string]string{}
	toUnset := []string{}

	for k, v := range env {
		if orig, ok := os.LookupEnv(k); ok {
			toRestore[k] = orig
		} else {
			toUnset = append(toUnset, k)
		}
		_ = os.Setenv(k, v)
	}

	return func() {
		for _, k := range toUnset {
			os.Unsetenv(k)
		}
		for k, v := range toRestore {
			os.Setenv(k, v)
		}
	}
}

func dockerCleanup() {
	_ = composeCmd("down", "-v")
}

func dockerRestart() error {
	return composeCmd("restart")
}

func dockerUp() error {
	return composeCmd("up", "-d")
}

func composeCmd(args ...string) error {
	args = append([]string{"compose", "-p", composeProjectName}, args...)
	cmd := exec.Command("docker", args...)
	cmd.Dir = "testdata/docker"
	return cmd.Run()
}

func merge(a, b map[string]string) map[string]string {
	new := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		new[k] = v
	}
	for k, v := range b {
		new[k] = v
	}
	return new
}

type assertOptions struct {
	domains        []string
	keyType        string
	keyLen         int
	shouldReuseKey bool
}

func (ao *assertOptions) assert(t *testing.T, v *vault.Client, wantVersion int) {
	data, err := v.KVv2(testKVMount).Get(context.Background(), "certs/"+ao.domains[0])
	if err != nil {
		t.Fatalf("error reading vault secret: %v", err)
	}

	if data.VersionMetadata.Version != wantVersion {
		t.Errorf("expected secret version %d, got %d", wantVersion, data.VersionMetadata.Version)
	}
	pub := data.Data[store.VaultKVKeyCert].(string)
	key := data.Data[store.VaultKVKeyKey].(string)
	ca := data.Data[store.VaultKVKeyCA].(string)
	pfx := data.Data[store.VaultKVKeyPFX].(string)

	cb, err := cert.BundleFromBytes([]byte(pub), []byte(key), []byte(ca))
	if err != nil {
		t.Errorf("error parsing cert: %v", err)
	}

	// Check if the key and cert match
	_, err = tls.X509KeyPair([]byte(pub), []byte(key))
	if err != nil {
		t.Errorf("error loading key pair: %v", err)
	}

	// The cert must chain to the CA
	certPool := x509.NewCertPool()
	for _, c := range cb.CA {
		certPool.AddCert(c)
	}
	_, err = cb.Certificate.Verify(x509.VerifyOptions{Roots: certPool})
	if err != nil {
		t.Errorf("error verifying cert against CA chain: %v", err)
	}

	if !reflect.DeepEqual(cb.Certificate.DNSNames, ao.domains) {
		t.Errorf("expected domains %#v, got %#v", ao.domains, cb.Certificate.DNSNames)
	}
	if cb.Certificate.Subject.CommonName != ao.domains[0] {
		t.Errorf("expected CN=%q, got CN=%q", ao.domains[0], cb.Certificate.Subject.CommonName)
	}

	pfxBytes, err := base64.StdEncoding.DecodeString(pfx)
	if err != nil {
		t.Fatalf("error decoding PFX: %v", err)
	}
	pfxKey, pfxCert, pfxCAs, err := pkcs12.DecodeChain(pfxBytes, "")
	if err != nil {
		t.Errorf("error decoding PFX: %v", err)
	}
	if !pfxCert.Equal(cb.Certificate) {
		t.Errorf("pfx certificate is different")
	}
	if !keysAreEqual(cb.PrivateKey, pfxKey) {
		t.Errorf("pfx private key not equal.")
	}
	if !reflect.DeepEqual(pfxCAs, cb.CA) {
		t.Errorf("PFX CAs doesn't match")
	}

	var keyType string
	var keyLen int
	switch k := cb.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyType = keyTypeRSA
		keyLen = k.N.BitLen()
	case *ecdsa.PrivateKey:
		keyType = keyTypeECDSA
		keyLen = k.Curve.Params().BitSize
	}
	if keyType != ao.keyType {
		t.Errorf("expected key type %q, got %q", ao.keyType, keyType)
	}
	if keyLen != ao.keyLen {
		t.Errorf("expected key type %d, got %d", ao.keyLen, keyLen)
	}

	if wantVersion > 1 {
		// We've already checked that the current version is what we want...
		oldData, err := v.KVv2(testKVMount).GetVersion(context.Background(), "certs/"+ao.domains[0], wantVersion-1)
		if err != nil {
			t.Fatalf("error reading vault version %d: %v", wantVersion, err)
		}

		oldCb, err := cert.BundleFromBytes(
			[]byte(oldData.Data[store.VaultKVKeyCert].(string)),
			[]byte(oldData.Data[store.VaultKVKeyKey].(string)),
			[]byte(oldData.Data[store.VaultKVKeyCA].(string)),
		)
		if err != nil {
			t.Fatalf("error parsing cert: %v", err)
		}

		keysAreSame := keysAreEqual(oldCb.PrivateKey, cb.PrivateKey)
		if ao.shouldReuseKey && !keysAreSame {
			t.Errorf("%s: expected private key to be reused, but keys were different", ao.domains[0])
		} else if !ao.shouldReuseKey && keysAreSame {
			// TODO
			t.Errorf("%s: expected private key to NOT be reused, but keys were same", ao.domains[0])
		}
	}
}

func keysAreEqual(a, b crypto.PrivateKey) bool {
	switch k := a.(type) {
	case *rsa.PrivateKey:
		return k.Equal(b)
	case *ecdsa.PrivateKey:
		return k.Equal(b)
	default:
		panic("unknown key type")
	}
}

func containerHealthCheck(t *testing.T) {
	checkURLs := []string{
		"https://localhost:14000/dir",
		"http://localhost:8080/health",
		vaultAddr + "/v1/sys/health",
	}

	var healthy int32

	client := http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	wg := sync.WaitGroup{}

	for _, url := range checkURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				r, err := client.Get(url)
				if err != nil {
					t.Logf("%q error: %v", url, err)
				} else if r.StatusCode > 199 && r.StatusCode < 300 {
					atomic.AddInt32(&healthy, 1)
					t.Logf("%q is healthy\n", url)
					return
				} else {
					t.Logf("%q returned %s", url, r.Status)
				}
				time.Sleep(500 * time.Millisecond)
			}
			t.Logf("%q is unhealthy\n", url)
		}(url)
	}
	wg.Wait()

	if int(healthy) != len(checkURLs) {
		t.Fatalf("%d/%d services healthy", healthy, len(checkURLs))
	}
}

func generateCerts() (func(), error) {
	if err := os.Mkdir(testCertDir, 0o755); err != nil {
		return nil, fmt.Errorf("error creating dir %q: %w", testCertDir, err)
	}
	pub, key, err := newSelfSigned("localhost")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path.Join(testCertDir, testServerCert), pub, 0o644); err != nil {
		return nil, fmt.Errorf("error writing cert: %w", err)
	}
	if err := os.WriteFile(path.Join(testCertDir, testServerKey), key, 0o644); err != nil {
		return nil, fmt.Errorf("error writing key: %w", err)
	}

	pub, key, err = newSelfSigned("client")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path.Join(testCertDir, testClientCert), pub, 0o644); err != nil {
		return nil, fmt.Errorf("error writing cert: %w", err)
	}
	if err := os.WriteFile(path.Join(testCertDir, testClientKey), key, 0o644); err != nil {
		return nil, fmt.Errorf("error writing key: %w", err)
	}

	return func() {
		_ = os.RemoveAll(testCertDir)
	}, nil
}

func configureVaultCertAuth(v *vault.Client) error {
	// First, create the policy
	vaultAdminPolicy := "admin"
	err := v.Sys().PutPolicy(vaultAdminPolicy, `
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
`)
	if err != nil {
		return err
	}

	err = v.Sys().EnableAuthWithOptions("cert", &vault.MountInput{Type: "cert"})
	if err != nil {
		return err
	}

	certPem, err := os.ReadFile(path.Join(testCertDir, testClientCert))
	if err != nil {
		return err
	}

	_, err = v.Logical().Write(
		"auth/cert/certs/client",
		map[string]interface{}{
			"name":           "client",
			"certificate":    string(certPem),
			"token_policies": []string{vaultAdminPolicy},
		},
	)
	return err
}

func assertAccountUnchanged(t *testing.T, v *vault.Client) {
	data, err := v.KVv2(testKVMount).Get(context.Background(), vaultAccountPath)
	if err != nil {
		t.Errorf("error checking account secret: %v", err)
		return
	}
	if data.VersionMetadata.Version != 1 {
		t.Errorf("expected account secret version 1, got %d", data.VersionMetadata.Version)
	}
}
