package tokenvalidationmiddleware

// Jwks collection of KSONWebKeys
type Jwks struct {
	Keys []JSONWebKeys `json:"keys,omitempty"`
}
