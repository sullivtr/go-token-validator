package tokenvalidationmiddleware

// OpenIDConfig is used to parse the response from the well known endpoint, and extract the jwks_uri
type OpenIDConfig struct {
	JwksURI string `json:"jwks_uri,omitempty"`
}
