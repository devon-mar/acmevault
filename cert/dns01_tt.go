//go:build !dns01all

package cert

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
)

func getDNS01Provider(name string) (challenge.Provider, error) {
	var err error
	var provider challenge.Provider

	if name == providerTempTxt {
		provider, err = NewTempTXTProvider()
	} else {
		return nil, fmt.Errorf("unsupported DNS01 provider %q", name)
	}
	return provider, err
}
