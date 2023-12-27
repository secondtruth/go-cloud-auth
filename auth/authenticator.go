package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/secondtruth/go-domain-auth/auth/backend"
	"github.com/secondtruth/go-domain-auth/auth/usermap"
)

type DomainAuthenticator struct {
	backend       backend.AuthBackend
	DefaultDomain string
	UserMap       usermap.UserMapper
}

func NewDomainAuthenticator(backend backend.AuthBackend) *DomainAuthenticator {
	return &DomainAuthenticator{
		backend: backend,
	}
}

func (a *DomainAuthenticator) Authenticate(username, password, domain string) (bool, error) {
	if domain == "" {
		domain = a.DefaultDomain
	}

	result, err := a.backend.Authenticate(username, password, domain)
	if err != nil {
		return false, fmt.Errorf("authentication backend error: %w", err)
	}

	return result, nil
}

func (a *DomainAuthenticator) AuthenticateMailAddress(mailAddress, password string) (bool, error) {
	parts := strings.Split(mailAddress, "@")
	if len(parts) != 2 {
		return false, errors.New("invalid mail address")
	}

	var realUsername string
	username := parts[0]
	domain := parts[1]
	if a.UserMap != nil && a.UserMap.IsAlias(username, domain) {
		var err error
		realUsername, err = a.UserMap.Resolve(username, domain)
		if err != nil {
			return false, fmt.Errorf("failed to resolve alias: %w", err)
		}
	} else {
		realUsername = username
	}

	return a.Authenticate(realUsername, password, domain)
}
