package cortex

type auth interface {
	Token() string
}

// APIAuth represents authentication by API token
type APIAuth struct {
	APIKey string
}

// Token returns API key and satisfies auth interface
func (a *APIAuth) Token() string {
	return "Bearer " + a.APIKey
}
