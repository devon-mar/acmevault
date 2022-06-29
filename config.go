package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/devon-mar/acmevault/cert"
)

const (
	envCerts     = "AV_CERTS"
	envExitError = "AV_EXIT_ERROR"

	certOptionKeyType    = "keytype"
	certOptionMustStaple = "muststaple"
	certOptionReuseKey   = "reusekey"
)

type config struct {
	certs       []certConfig
	exitOnError bool
}

func configFromEnv() (*config, error) {
	cfg := &config{}

	for _, c := range strings.Split(os.Getenv(envCerts), "\n") {
		if c == "" {
			continue
		}
		cc, err := parseCert(c)
		if err != nil {
			return nil, fmt.Errorf("error parsing cert: %w", err)
		}
		cfg.certs = append(cfg.certs, *cc)
	}
	cfg.exitOnError, _ = strconv.ParseBool(os.Getenv(envExitError))

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *config) validate() error {
	if len(c.certs) == 0 {
		return errors.New("0 certs found")
	}
	for _, cc := range c.certs {
		if err := cc.validate(); err != nil {
			return err
		}
	}
	return nil
}

type certConfig struct {
	cert.CertRequest
	reuseKey bool
}

func (c *certConfig) validate() error {
	if len(c.Domains) == 0 {
		return errors.New("cannot have 0 domains")
	}
	return nil
}

func parseCert(s string) (*certConfig, error) {
	cfg := &certConfig{}

	split := strings.Split(s, ",")

	var options []string

	for i, d := range split {
		if strings.Contains(d, "=") {
			// we're done parsing domains
			options = split[i:]
			break
		}
		trimmed := strings.TrimSpace(d)
		if len(trimmed) == 0 {
			continue
		}
		cfg.Domains = append(cfg.Domains, trimmed)
	}

	for _, o := range options {
		k, v := splitKV(strings.TrimSpace(o))
		if k == "" || v == "" {
			return nil, fmt.Errorf("empty key or value: %q", o)
		}

		switch k {
		case certOptionKeyType:
			cfg.KeyType = v
		case certOptionMustStaple:
			cfg.MustStaple, _ = strconv.ParseBool(v)
		case certOptionReuseKey:
			cfg.reuseKey, _ = strconv.ParseBool(v)
		default:
			return nil, fmt.Errorf("unsupported cert option %q", k)
		}
	}
	return cfg, nil
}

func splitKV(s string) (string, string) {
	split := strings.SplitN(s, "=", 2)
	if len(split) != 2 {
		return split[0], ""
	}
	return split[0], split[1]
}
