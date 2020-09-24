package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

func main() {
	t := jwt.New()
	t.Set(jwt.IssuerKey, "http://fake-idp-issuer/")
	t.Set(jwt.SubjectKey, "0b13f81b-2c57-4921-b6b2-a913a9307707")
	t.Set(jwt.AudienceKey, "http://fake-idp-aud/")
	// t.Set(jwt.IssuedAtKey, 1600645295)
	// t.Set(jwt.ExpirationKey, 1600645295)
	// t.Set(jwt.NotBeforeKey, 1600645295)
	t.Set(jwt.JwtIDKey, "id123456")
	t.Set("scope", "testscope")
	t.Set("typ", "Bearer")
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	kid := "unittest"
	hdrs := jws.NewHeaders()
	err = hdrs.Set(jws.KeyIDKey, kid)
	if err != nil {
		panic(err)
	}
	token, err := jwt.Sign(t, jwa.RS256, privKey, jwt.WithHeaders(hdrs))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(token))
}
