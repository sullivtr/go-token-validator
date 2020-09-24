package tokenvalidationmiddleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// TokenValidationMiddleware represents the configuration for the validation middleware
type TokenValidationMiddleware struct {
	Options Options
}

// New creates a new instance of the middleware
func New() *TokenValidationMiddleware {
	return &TokenValidationMiddleware{
		Options: Options{},
	}
}

// NewWithOptions creates a new instance of the middleware using the provided options
func NewWithOptions(opts Options) *TokenValidationMiddleware {
	return &TokenValidationMiddleware{
		Options: opts,
	}
}

func contains(s []string, in string) bool {
	for _, a := range s {
		if a == in {
			return true
		}
	}
	return false
}

// NewRSA256Validator will issue a new instance of the TokenValidationMiddleware that uses RS256 validation for a Bearer token
func NewRSA256Validator(options *Options) *TokenValidationMiddleware {
	return NewWithOptions(Options{
		ValidationKeyFunc: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			if options.VerifyAudience {
				aud := options.Audience

				tokenAud := token.Claims.(jwt.MapClaims)["aud"]

				switch tokenAud := tokenAud.(type) {
				case string:
					checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
					if !checkAud {
						return token, errors.New("Invalid audience")
					}
				case []string:
					if !contains(tokenAud, aud) {
						return token, errors.New("Invalid audience")
					}
				}
			}
			// Verify 'iss' claim
			if options.VerifyIssuer {
				iss := options.Issuer
				checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, true)
				if !checkIss {
					return token, errors.New("Invalid issuer")
				}
			}
			cert, err := getPemCert(token, options.Issuer)
			if err != nil {
				return token, errors.New("Unable to get signing key")
			}
			return cert, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})

}

// ValidateBearerToken will validate the cliams of the incoming auth token
func (m *TokenValidationMiddleware) ValidateBearerToken(r *http.Request) (bool, error) {
	// Extract bearer token from auth header
	t, err := GetBearerToken(r)
	if err != nil {
		return false, fmt.Errorf("Error extracting token: %w", err)
	}
	pt, err := jwt.Parse(t, m.Options.ValidationKeyFunc)
	if err != nil {
		return false, fmt.Errorf("Error parsing token: %w", err)
	}
	if m.Options.SigningMethod != nil && m.Options.SigningMethod.Alg() != pt.Header["alg"] {
		message := fmt.Sprintf("Expected %s signing method but token specified %s",
			m.Options.SigningMethod.Alg(),
			pt.Header["alg"])
		return false, fmt.Errorf("Error validating token algorithm: %s", message)
	}
	if !pt.Valid {
		return false, errors.New("Token is invalid")
	}
	nr := r.WithContext(context.WithValue(r.Context(), "user", pt))
	*r = *nr
	return true, nil
}

// GetBearerToken extracts a bearer token from the request Authorization header
func GetBearerToken(r *http.Request) (string, error) {
	authHeaderParts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}
	return authHeaderParts[1], nil
}

// ValidateScope validates the presense of a specific scope on a bearer token
func ValidateScope(scope string, tokenString string) bool {
	token, _ := jwt.ParseWithClaims(tokenString, &Claims{}, nil)
	if token == nil {
		return false
	}
	claims, _ := token.Claims.(*Claims)

	hasScope := false
	result := strings.Split(claims.Scope, " ")
	for i := range result {
		if result[i] == scope {
			hasScope = true
		}
	}

	return hasScope
}

// RequestHasScope checks for a scope in the token in the Authorization Header of the Request
func RequestHasScope(scope string, r *http.Request) bool {
	token, err := GetBearerToken(r)
	if err != nil {
		return false
	}
	return ValidateScope(scope, token)
}

var httpClient = &http.Client{}

// getPemCert uses the IDP well-known endpoint to collect modulus and exponent to construct an XC5 public key
func getPemCert(token *jwt.Token, issuer string) (*rsa.PublicKey, error) {
	var openIDConfig OpenIDConfig

	nStr := ""
	eStr := ""

	var cert *rsa.PublicKey

	wke := fmt.Sprintf("%s.well-known/openid-configuration", issuer)
	resp, err := httpClient.Get(wke)
	if err != nil {
		return cert, err
	}

	// read the payload
	body, err := ioutil.ReadAll(resp.Body)

	defer resp.Body.Close()

	if err != nil {
		return cert, err
	}

	err = json.Unmarshal(body, &openIDConfig)
	if err != nil {
		return cert, err
	}

	jwksResp, err := httpClient.Get(openIDConfig.JwksURI)
	if err != nil {
		return cert, err
	}

	var jwks = Jwks{}
	err = json.NewDecoder(jwksResp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			nStr = jwks.Keys[k].N
			eStr = jwks.Keys[k].E
		}
	}

	if nStr == "" || eStr == "" {
		err := errors.New("Unable to find appropriate key")
		return cert, err
	}

	cert = genXC5(nStr, eStr)

	return cert, nil
}

func genXC5(nStr string, eStr string) *rsa.PublicKey {
	// decode the base64 bytes for n
	nb, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		log.Fatal(err)
	}

	// The default exponent is usually 65537
	e := 65537
	if eStr != "AQAB" && eStr != "AAEAAQ" {
		log.Fatal("need to decode e:", eStr)
	}

	var pubKey = &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}

	return pubKey
}
