package tokenvalidationmiddleware

import "github.com/dgrijalva/jwt-go"

// Claims defines the claims to validate against during token validation
type Claims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}
