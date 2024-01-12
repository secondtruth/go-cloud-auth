package backend

type MultiAuthBackend struct {
	backends []AuthBackend
}

func NewMultiAuthBackend(backends ...AuthBackend) *MultiAuthBackend {
	return &MultiAuthBackend{backends: backends}
}

func (b *MultiAuthBackend) Authenticate(username, password, domain string) (bool, error) {
	for _, backend := range b.backends {
		if ok, err := backend.Authenticate(username, password, domain); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}
