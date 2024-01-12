package backend

type UserListDomainsMap map[string]CredentialsMap

type CredentialsMap map[string]string

type SimpleAuthBackend struct {
	userlist UserListDomainsMap
}

func NewSimpleAuthBackend(userlist UserListDomainsMap) *SimpleAuthBackend {
	return &SimpleAuthBackend{userlist: userlist}
}

func (b *SimpleAuthBackend) Authenticate(username, password, domain string) (bool, error) {
	if _, ok := b.userlist[domain]; !ok {
		return false, nil
	}
	if _, ok := b.userlist[domain][username]; !ok {
		return false, nil
	}
	if b.userlist[domain][username] != password {
		return false, nil
	}
	return true, nil
}
