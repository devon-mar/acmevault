package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	log "github.com/sirupsen/logrus"
)

const (
	EnvTTDebug         = "TEMPTXT_DEBUG"
	EnvTTURL           = "TEMPTXT_URL"
	EnvTTCert          = "TEMPTXT_CERT"
	EnvTTKey           = "TEMPTXT_KEY"
	EnvTTCA            = "TEMPTXT_CA"
	tempTxtKeyfQDN     = "fqdn"
	tempTxtKeyContent  = "content"
	tempTxtDebugHeader = "X-Forwarded-User"
	tempTxtDebugUser   = "user"
)

type TempTXTProvider struct {
	url    string
	client http.Client
	debug  bool
}

func NewTempTXTProvider() (*TempTXTProvider, error) {
	p := &TempTXTProvider{}
	transport, err := getTransport()
	if err != nil {
		return nil, err
	}
	p.client = http.Client{Timeout: time.Second * 2, Transport: transport}
	p.debug, _ = strconv.ParseBool(os.Getenv(EnvTTDebug))

	p.url, err = readEnv(EnvTTURL)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func getTransport() (*http.Transport, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	tlsCfg := &tls.Config{}

	certPath := os.Getenv(EnvTTCert)
	keyPath := os.Getenv(EnvTTKey)
	caPath := os.Getenv(EnvTTCA)

	if caPath != "" {
		pool := x509.NewCertPool()
		cert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("error reading CA: %w", err)
		}
		pool.AppendCertsFromPEM(cert)
		tlsCfg.RootCAs = pool
	}
	if certPath != "" && keyPath != "" {
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("error reading client key pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{c}
	}
	transport.TLSClientConfig = tlsCfg
	return transport, nil
}

func (p *TempTXTProvider) set(fqdn string, value string) error {
	values := url.Values{tempTxtKeyfQDN: {fqdn}, tempTxtKeyContent: {value}}
	req, err := http.NewRequest(http.MethodPut, p.url, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.debug {
		req.Header.Set(tempTxtDebugHeader, tempTxtDebugUser)
	}
	log.WithFields(log.Fields{"fqdn": fqdn, "content": value}).Debugf("Sending update to %q", p.url)
	r, err := p.client.Do(req)
	if err != nil {
		return err
	}
	if r.StatusCode < 200 || r.StatusCode > 299 {
		return fmt.Errorf("got status %d", r.StatusCode)
	}

	return nil
}

// CleanUp implements challenge.Provider
func (p *TempTXTProvider) CleanUp(domain string, token string, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	err := p.set(fqdn, "")
	if err != nil {
		return fmt.Errorf("temptxt: %w", err)
	}
	return nil
}

// Present implements challenge.Provider
func (p *TempTXTProvider) Present(domain string, token string, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	err := p.set(fqdn, value)
	if err != nil {
		return fmt.Errorf("temptxt: %w", err)
	}
	return nil
}
