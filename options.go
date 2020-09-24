package tokenvalidationmiddleware

import (
	"github.com/dgrijalva/jwt-go"
)

// Options represents the configuration options for the routers token validation middleware
type Options struct {
	Issuer            string
	Audience          string
	VerifyIssuer      bool
	VerifyAudience    bool
	ValidationKeyFunc jwt.Keyfunc
	SigningMethod     jwt.SigningMethod
}
