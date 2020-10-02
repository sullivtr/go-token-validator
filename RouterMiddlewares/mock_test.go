package routermiddlewares

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	exponent = "AQAB"
	audience = "http://fake-idp-aud/"
)

func genToken(privateKey *rsa.PrivateKey, iss string, expired bool) string {
	t := jwt.New()
	_ = t.Set(jwt.IssuerKey, iss)
	_ = t.Set(jwt.SubjectKey, "0b13f81b-2c57-4921-b6b2-a913a9307707")
	_ = t.Set(jwt.AudienceKey, audience)
	_ = t.Set(jwt.JwtIDKey, "id123456")
	_ = t.Set("scope", "testscope")
	_ = t.Set("typ", "Bearer")
	if expired {
		_ = t.Set(jwt.IssuedAtKey, 1600645295)
		_ = t.Set(jwt.ExpirationKey, 1600645295)
		_ = t.Set(jwt.NotBeforeKey, 1600645295)
	}

	kid := "unittest"
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)

	token, _ := jwt.Sign(t, jwa.RS256, privateKey, jwt.WithHeaders(hdrs))
	return "Bearer " + string(token)
}

func getModulus(key *rsa.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(key.N.Bytes())
}

type mockReq struct {
	URI  string
	Body interface{}
}

func newMockServer(reqs ...*mockReq) *httptest.Server {
	handler := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			for _, proc := range reqs {
				if proc.URI == r.URL.RequestURI() && r.Method == "GET" {
					w.WriteHeader(http.StatusOK)
					bytes, _ := json.Marshal(proc.Body)
					_, _ = w.Write(bytes)
					return
				}
			}

			w.WriteHeader(http.StatusNotFound)
		})

	return httptest.NewServer(handler)
}
