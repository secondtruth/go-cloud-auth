package backend

type AuthBackend interface {
	Authenticate(username, password, domain string) (bool, error)
}
