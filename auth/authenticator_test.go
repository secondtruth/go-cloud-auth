package auth

import (
	"errors"
	"testing"
)

type MockAuthBackend struct {
	AuthenticateFunc func(string, string, string) (bool, error)
}

func (m *MockAuthBackend) Authenticate(username, password, domain string) (bool, error) {
	return m.AuthenticateFunc(username, password, domain)
}

// MockUserMap is a mock implementation of UserMap for testing
type MockUserMap struct {
	IsAliasFunc func(string, string) bool
	ResolveFunc func(string, string) (string, error)
}

func (m *MockUserMap) IsAlias(username, domain string) bool {
	return m.IsAliasFunc(username, domain)
}

func (m *MockUserMap) Resolve(username, domain string) (string, error) {
	return m.ResolveFunc(username, domain)
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		password      string
		domain        string
		defaultDomain string
		want          bool
		wantErr       bool
	}{
		{
			name:     "invalid credentials",
			username: "unknown",
			password: "unknown",
			domain:   "domain.com",
			want:     false,
			wantErr:  false,
		},
		{
			name:     "valid credentials",
			username: "realuser",
			password: "Pa$$word",
			domain:   "domain.com",
			want:     true,
			wantErr:  false,
		},
		{
			name:          "valid credentials with default domain",
			username:      "realuser",
			password:      "Pa$$word",
			domain:        "",
			defaultDomain: "domain.com",
			want:          true,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authBackend := &MockAuthBackend{
				AuthenticateFunc: func(username, password, domain string) (bool, error) {
					return username == "realuser" && password == "Pa$$word" && domain == "domain.com", nil
				},
			}
			a := NewDomainAuthenticator(authBackend)
			if tt.defaultDomain != "" {
				a.DefaultDomain = tt.defaultDomain
			}
			got, err := a.Authenticate(tt.username, tt.password, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticateMailAddress(t *testing.T) {
	tests := []struct {
		name        string
		mailAddress string
		password    string
		userMap     *MockUserMap
		want        bool
		wantErr     bool
	}{
		{
			name:        "invalid mail address",
			mailAddress: "invalid",
			password:    "Pa$$word",
			want:        false,
			wantErr:     true,
		},
		{
			name:        "valid mail address",
			mailAddress: "realuser@domain.com",
			password:    "Pa$$word",
			want:        true,
			wantErr:     false,
		},
		{
			name:        "valid mail address with alias",
			mailAddress: "alias@domain.com",
			password:    "Pa$$word",
			userMap: &MockUserMap{
				IsAliasFunc: func(username, domain string) bool {
					return username == "alias"
				},
				ResolveFunc: func(username, domain string) (string, error) {
					if username == "alias" {
						return "realuser", nil
					}
					return "", errors.New("failed to resolve alias")
				},
			},
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authBackend := &MockAuthBackend{
				AuthenticateFunc: func(username, password, domain string) (bool, error) {
					return username == "realuser" && password == "Pa$$word" && domain == "domain.com", nil
				},
			}
			a := NewDomainAuthenticator(authBackend)
			if tt.userMap != nil {
				a.UserMap = tt.userMap
			}
			got, err := a.AuthenticateMailAddress(tt.mailAddress, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthenticateMailAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AuthenticateMailAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}
