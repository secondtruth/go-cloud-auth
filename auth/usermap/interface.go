package usermap

type UserMapper interface {
	IsAlias(name, domain string) bool
	Resolve(alias, domain string) (string, error)
}
