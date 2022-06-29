package main

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/devon-mar/acmevault/cert"
)

func TestConfigFromEnv(t *testing.T) {
	tests := map[string]struct {
		certsEnv    string
		exitOnError string

		want      *config
		wantError bool
	}{
		"empty env": {
			certsEnv:    "",
			exitOnError: "",
			wantError:   true,
		},
		"one": {
			certsEnv:    "cert.example.com",
			exitOnError: "true",
			want: &config{
				certs: []certConfig{
					{CertRequest: cert.CertRequest{Domains: []string{"cert.example.com"}}},
				},
				exitOnError: true,
			},
		},
		"invalid option": {
			certsEnv:  "cert.example.com,invalid=true",
			wantError: true,
		},
		"option key no val": {
			certsEnv:  fmt.Sprintf("cert.example.com,%s=", certOptionKeyType),
			wantError: true,
		},
		"option only =": {
			certsEnv:  "cert.example.com,=",
			wantError: true,
		},
		"domain after option": {
			certsEnv:  fmt.Sprintf("cert.example.com,%s=true,cert2.example.com", certOptionKeyType),
			wantError: true,
		},
		"options only": {
			certsEnv:  fmt.Sprintf(",%s=true", certOptionMustStaple),
			wantError: true,
		},
		"with options": {
			certsEnv: fmt.Sprintf(
				"cert.example.com,cert2.example.com,%s=RSA4096,%s=true,%s=true",
				certOptionKeyType, certOptionMustStaple, certOptionReuseKey,
			),
			exitOnError: "false",
			want: &config{
				certs: []certConfig{
					{
						CertRequest: cert.CertRequest{
							Domains:    []string{"cert.example.com", "cert2.example.com"},
							MustStaple: true,
							KeyType:    "RSA4096",
						},
						reuseKey: true,
					},
				},
				exitOnError: false,
			},
		},
		"two": {
			certsEnv: `cert.example.com,cert2.example.com
test.example.com,test2.example.com
`,
			want: &config{
				certs: []certConfig{
					{CertRequest: cert.CertRequest{Domains: []string{"cert.example.com", "cert2.example.com"}}},
					{CertRequest: cert.CertRequest{Domains: []string{"test.example.com", "test2.example.com"}}},
				},
			},
		},
		"extra newline": {
			certsEnv: `cert.example.com,cert2.example.com

test.example.com,test2.example.com
`,
			want: &config{
				certs: []certConfig{
					{CertRequest: cert.CertRequest{Domains: []string{"cert.example.com", "cert2.example.com"}}},
					{CertRequest: cert.CertRequest{Domains: []string{"test.example.com", "test2.example.com"}}},
				},
			},
		},
		"trailing and leading spaces": {
			certsEnv: " cert.example.com ,cert2.example.com ",
			want: &config{
				certs: []certConfig{
					{CertRequest: cert.CertRequest{Domains: []string{"cert.example.com", "cert2.example.com"}}},
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			setEnvs(t, map[string]string{envCerts: tc.certsEnv, envExitError: tc.exitOnError})

			have, err := configFromEnv()
			if err == nil && tc.wantError {
				t.Error("expected an error")
			} else if err != nil && !tc.wantError {
				t.Errorf("expected no error but got: %v", err)
			}
			if !reflect.DeepEqual(have, tc.want) {
				t.Errorf("got %#v, want %#v", have, tc.want)
			}
		})
	}
}

func setEnvs(t *testing.T, kv map[string]string) {
	for k, v := range kv {
		if err := os.Setenv(k, v); err != nil {
			log.Fatalf("error setting env: %v", err)
		}
	}
}
