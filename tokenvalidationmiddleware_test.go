package tokenvalidationmiddleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

type mockOIDCRequest struct {
	URI  string
	Body interface{}
}

const (
	exponent = "AQAB"
	issuer   = "http://fake-idp-issuer/"
	audience = "http://fake-idp-aud/"
	jwksURI  = "http://fake-idp-issuer/jwks/"
	kid      = "unittest"
)

var (
	jwksURIReqValid = mockOIDCRequest{
		URI: "http://fake-idp-issuer/.well-known/openid-configuration",
		Body: OpenIDConfig{
			JwksURI: jwksURI,
		},
	}
)

func genToken(privateKey *rsa.PrivateKey, expired bool) string {
	t := jwt.New()
	_ = t.Set(jwt.IssuerKey, issuer)
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

// func TestGetToken(t *testing.T) {
// 	key, _ := rsa.GenerateKey(rand.Reader, 2048)
// 	tkn := genToken(key, false)
// 	fmt.Println(tkn)
// }

func TestNew(t *testing.T) {
	v := New()
	assert.NotNil(t, v)
	assert.NotNil(t, v.Options)
}

func TestNewRSA256ValidatorNoJwks(t *testing.T) {
	httpmock.ActivateNonDefault(httpClient)
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("GET", jwksURI, httpmock.NewJsonResponderOrPanic(200, Jwks{
		Keys: []JSONWebKeys{
			{
				N:   "bad-mod",
				E:   "bad-exponent",
				Kid: kid,
			},
		},
	}))

	v := NewRSA256Validator(&Options{
		Audience:       audience,
		Issuer:         issuer,
		VerifyAudience: true,
		VerifyIssuer:   true,
	})
	assert.NotNil(t, v)
	req, err := http.NewRequest(http.MethodGet, "http://fake-url-for-test.com", nil)
	assert.NoError(t, err)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := genToken(key, false)

	req.Header.Add("Authorization", token)
	tokenIsValid, err := v.ValidateBearerToken(req)
	assert.Error(t, err)
	assert.False(t, tokenIsValid)
}

func TestNewRSA256Validator(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := []struct {
		token       string
		issuer      string
		audience    string
		expectation bool
		message     string
	}{
		// {token: genToken(key, false), issuer: issuer, audience: audience, expectation: true, message: "valid token should return true"},
		// {token: genToken(key, true), issuer: issuer, audience: audience, expectation: false, message: "expired token should return false"},
		// {token: "invalidtoken", issuer: issuer, audience: audience, expectation: false, message: "invalidtoken should return false"},
		// {token: "", issuer: issuer, audience: audience, expectation: false, message: "empty token should return false"},
		// {token: genToken(key, false), issuer: "invalidissuer", audience: audience, expectation: false, message: "invalidissuer should return false"},
		{token: genToken(key, false), issuer: issuer, audience: "invalidaudience", expectation: false, message: "invalidaudience should return false"},
	}

	for _, c := range cases {
		httpmock.ActivateNonDefault(httpClient)
		defer httpmock.DeactivateAndReset()
		httpmock.RegisterResponder("GET", jwksURIReqValid.URI, httpmock.NewJsonResponderOrPanic(200, OpenIDConfig{
			JwksURI: jwksURI,
		}))
		httpmock.RegisterResponder("GET", jwksURI, httpmock.NewJsonResponderOrPanic(200, Jwks{
			Keys: []JSONWebKeys{
				{
					N:   getModulus(key),
					E:   exponent,
					Kid: kid,
				},
			},
		}))

		v := NewRSA256Validator(&Options{
			Audience:       c.audience,
			Issuer:         c.issuer,
			VerifyAudience: true,
			VerifyIssuer:   true,
		})
		assert.NotNil(t, v)
		req, err := http.NewRequest(http.MethodGet, "http://fake-url-for-test.com", nil)
		assert.NoError(t, err)

		req.Header.Add("Authorization", c.token)
		tokenIsValid, err := v.ValidateBearerToken(req)
		assert.Equal(t, c.expectation, tokenIsValid, c.message)
		if c.expectation {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}
	}
}

func TestRequestHasScope(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := genToken(key, false)
	cases := []struct {
		token       string
		testScope   string
		expectation bool
	}{
		{token: token, testScope: "testscope", expectation: true},
		{token: "", testScope: "testscope", expectation: false},
	}

	for _, c := range cases {
		req, err := http.NewRequest(http.MethodGet, "http://fake-url-for-test.com", nil)
		if err != nil {
			assert.Fail(t, "unable to construct httpRequest for unit test")
		}
		req.Header.Add("Authorization", c.token)

		assert.Equal(t, c.expectation, RequestHasScope("testscope", req))
	}
}

func TestGetBearerToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := genToken(key, false)

	cases := []struct {
		token         string
		testScope     string
		expectation   string
		expectedError bool
	}{
		{token: token, testScope: "testscope", expectation: strings.Replace(token, "Bearer ", "", 1), expectedError: false},
		{token: "", testScope: "testscope", expectation: "", expectedError: true},
	}

	for _, c := range cases {
		req, err := http.NewRequest(http.MethodGet, "http://fake-url-for-test.com", nil)
		if err != nil {
			assert.Fail(t, "unable to construct httpRequest for unit test")
		}
		req.Header.Add("Authorization", c.token)

		token, err := GetBearerToken(req)
		assert.Equal(t, c.expectation, token)
		if c.expectedError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestValidateScope(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := genToken(key, false)
	cases := []struct {
		token       string
		testScope   string
		expectation bool
	}{
		{token: strings.Replace(token, "Bearer ", "", 1), testScope: "testscope", expectation: true},
		{token: strings.Replace(token, "Bearer ", "", 1), testScope: "missingscope", expectation: false},
		{token: "", testScope: "testscope", expectation: false},
	}

	for _, c := range cases {
		assert.Equal(t, c.expectation, ValidateScope(c.testScope, c.token), "expected: %s", c.testScope)
	}
}
