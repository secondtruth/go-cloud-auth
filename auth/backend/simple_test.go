package backend

import (
	"testing"
)

func TestNewSimpleAuthBackend(t *testing.T) {
	userlist := UserListDomainsMap{
		"domain.com": CredentialsMap{
			"user": "password",
		},
	}

	backend := NewSimpleAuthBackend(userlist)

	if backend == nil {
		t.Errorf("NewSimpleAuthBackend() = %v, want non-nil", backend)
	}
}

func TestSimpleAuthBackend_Authenticate(t *testing.T) {
	userlist := UserListDomainsMap{
		"domain.com": CredentialsMap{
			"user": "password",
		},
	}

	backend := NewSimpleAuthBackend(userlist)

	tests := []struct {
		name     string
		username string
		password string
		domain   string
		want     bool
	}{
		{
			name:     "valid credentials",
			username: "user",
			password: "password",
			domain:   "domain.com",
			want:     true,
		},
		{
			name:     "invalid domain",
			username: "user",
			password: "password",
			domain:   "wrongdomain.com",
			want:     false,
		},
		{
			name:     "invalid username",
			username: "wronguser",
			password: "password",
			domain:   "domain.com",
			want:     false,
		},
		{
			name:     "invalid password",
			username: "user",
			password: "wrongpassword",
			domain:   "domain.com",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := backend.Authenticate(tt.username, tt.password, tt.domain)
			if got != tt.want {
				t.Errorf("Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}
