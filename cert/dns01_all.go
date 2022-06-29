//go:build dns01all

package cert

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
)

func getDNS01Provider(name string) (challenge.Provider, error) {
	var err error
	var provider challenge.Provider

	if name == providerTempTxt {
		provider, err = NewTempTXTProvider()
	} else {
		provider, err = dns.NewDNSChallengeProviderByName(name)
	}
	if err != nil {
		return nil, fmt.Errorf("error initializing DNS01 provider: %w", err)
	}
	return provider, nil
}
