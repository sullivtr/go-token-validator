package tokenvalidationmiddleware

// JSONWebKeys model for the signing key
type JSONWebKeys struct {
	Kty string   `json:"kty,omitempty"`
	Kid string   `json:"kid,omitempty"`
	Use string   `json:"use,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}
