package backend

import (
	"errors"
	"testing"
)

type mockAuthBackend struct {
	shouldAuthenticate bool
	err                error
}

func (m *mockAuthBackend) Authenticate(username, password, domain string) (bool, error) {
	return m.shouldAuthenticate, m.err
}

func TestMultiAuthBackend_Authenticate(t *testing.T) {
	tests := []struct {
		name     string
		backends []AuthBackend
		want     bool
		wantErr  bool
	}{
		{
			name:     "no backends",
			backends: []AuthBackend{},
			want:     false,
			wantErr:  false,
		},
		{
			name: "one backend, authenticates",
			backends: []AuthBackend{
				&mockAuthBackend{shouldAuthenticate: true},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "one backend, does not authenticate",
			backends: []AuthBackend{
				&mockAuthBackend{shouldAuthenticate: false},
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "multiple backends, one authenticates",
			backends: []AuthBackend{
				&mockAuthBackend{shouldAuthenticate: false},
				&mockAuthBackend{shouldAuthenticate: true},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "multiple backends, none authenticate",
			backends: []AuthBackend{
				&mockAuthBackend{shouldAuthenticate: false},
				&mockAuthBackend{shouldAuthenticate: false},
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "backend returns error",
			backends: []AuthBackend{
				&mockAuthBackend{err: errors.New("error")},
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewMultiAuthBackend(tt.backends...)
			got, err := b.Authenticate("username", "password", "domain.com")
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
