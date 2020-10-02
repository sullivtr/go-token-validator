package routermiddlewares

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	tvm "github.com/tyler-technologies/go-token-validator"
)

func TestEcho(t *testing.T) {
	cases := []struct {
		expired bool
		code    int
	}{
		{expired: false, code: http.StatusOK},
		{expired: true, code: http.StatusUnauthorized},
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	wkeReq := &mockReq{URI: "/.well-known/openid-configuration"}
	jwksReq := &mockReq{URI: "/"}

	mockServer := newMockServer(wkeReq, jwksReq)
	defer mockServer.Close()

	wkeReq.Body = tvm.OpenIDConfig{JwksURI: mockServer.URL}
	jwksReq.Body = tvm.Jwks{Keys: []tvm.JSONWebKeys{{N: getModulus(key), E: exponent, Kid: "unittest"}}}

	e := echo.New()
	e.Use(Echo(tvm.Options{
		Audience:       audience,
		VerifyAudience: true,
		Issuer:         mockServer.URL,
		VerifyIssuer:   true,
	}))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	for _, c := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		req.Header.Add("Authorization", genToken(key, mockServer.URL, c.expired))
		e.ServeHTTP(rec, req)
		assert.Equal(t, c.code, rec.Code)
	}
}
