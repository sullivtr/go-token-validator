package tokenvalidationmiddleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	gojwt "github.com/dgrijalva/jwt-go"
	"github.com/jarcoal/httpmock"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/suite"
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
		URI: "http://fake-idp-issuer/",
		Body: OpenIDConfig{
			JwksURI: jwksURI,
		},
	}
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

type TokenValidationSuite struct {
	suite.Suite
}

func TestTokenValidationSuite(t *testing.T) {
	suite.Run(t, new(TokenValidationSuite))
}

func (suite TokenValidationSuite) TestNew() {
	v := New()
	suite.NotNil(v)
	suite.NotNil(v.Options)
}

func (suite TokenValidationSuite) TestNewRSA256Validator() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := []struct {
		token       string
		issuer      string
		audience    string
		expectation bool
		message     string
	}{
		{token: genToken(key, issuer, false), issuer: issuer, audience: audience, expectation: true, message: "valid token should return true"},
		{token: genToken(key, "http://wrong-response/", false), issuer: "http://wrong-response/", audience: audience, expectation: false, message: "invalid well-known response should fail to unmarshal response"},
		{token: genToken(key, "http://bad-jwks-uri/", false), issuer: "http://bad-jwks-uri/", audience: audience, expectation: false, message: "invalid jwksuri response should fail when calling bad url"},
		{token: genToken(key, "http://bad-jwks-response/", false), issuer: "http://bad-jwks-response/", audience: audience, expectation: false, message: "invalid jwks response should fail when calling unmarshalling jwks"},
		{token: genToken(key, "http://empty-keys/", false), issuer: "http://empty-keys/", audience: audience, expectation: false, message: "empty keys in the jwks response should fail when calling unmarshalling jwks"},
		{token: genToken(key, "http://genxc5-error/", false), issuer: "http://genxc5-error/", audience: audience, expectation: false, message: "bad keys in jwks should fail when generating public key"},
		{token: genToken(key, issuer, true), issuer: issuer, audience: audience, expectation: false, message: "expired token should return false"},
		{token: "invalidtoken", issuer: issuer, audience: audience, expectation: false, message: "invalidtoken should return false"},
		{token: "", issuer: issuer, audience: audience, expectation: false, message: "empty token should return false"},
		{token: genToken(key, issuer, false), issuer: "invalidissuer", audience: audience, expectation: false, message: "invalidissuer should return false"},
		{token: genToken(key, issuer, false), issuer: issuer, audience: "invalidaudience", expectation: false, message: "invalidaudience should return false"},
		{token: genToken(key, "http://error-responder/", false), issuer: "http://error-responder/", audience: audience, expectation: false, message: "bad jwks keys should return false"},
	}

	httpmock.ActivateNonDefault(httpClient)
	defer httpmock.DeactivateAndReset()

	registerWK := func(baseUrl string, response interface{}) {
		httpmock.RegisterResponder("GET", baseUrl+"/.well-known/openid-configuration", httpmock.NewJsonResponderOrPanic(200, response))
	}

	registerWK("http://wrong-response", "bad-json")
	registerWK("http://bad-jwks-uri", OpenIDConfig{JwksURI: "non-url"})
	registerWK("http://bad-jwks-response", OpenIDConfig{JwksURI: "http://give-me-bad-jwks.com"})
	httpmock.RegisterResponder("GET", "http://give-me-bad-jwks.com", httpmock.NewJsonResponderOrPanic(200, "bad-jwks"))

	registerWK("http://empty-keys", OpenIDConfig{JwksURI: "http://empty-keys"})
	httpmock.RegisterResponder("GET", "http://empty-keys", httpmock.NewJsonResponderOrPanic(200, Jwks{Keys: []JSONWebKeys{{Kid: kid}}}))

	registerWK("http://genxc5-error", OpenIDConfig{JwksURI: "http://genxc5-error"})
	httpmock.RegisterResponder("GET", "http://genxc5-error", httpmock.NewJsonResponderOrPanic(200, Jwks{Keys: []JSONWebKeys{{N: "-", E: "-", Kid: "unittest"}}}))

	httpmock.RegisterResponder("GET", "http://error-responder/.well-known/openid-configuration", httpmock.NewErrorResponder(errors.New("error")))

	registerWK("http://fake-idp-issuer", OpenIDConfig{JwksURI: "http://fake-idp-issuer"})
	httpmock.RegisterResponder("GET", "http://fake-idp-issuer", httpmock.NewJsonResponderOrPanic(200, Jwks{
		Keys: []JSONWebKeys{
			{
				N:   getModulus(key),
				E:   exponent,
				Kid: kid,
			},
		},
	}))

	for _, c := range cases {
		v := NewRSA256Validator(&Options{
			Audience:       c.audience,
			Issuer:         c.issuer,
			VerifyAudience: true,
			VerifyIssuer:   true,
		})
		suite.NotNil(v)
		req, err := http.NewRequest(http.MethodGet, "http://fake-url-for-test.com", nil)
		suite.NoError(err)

		req.Header.Add("Authorization", c.token)
		tokenIsValid, err := v.ValidateBearerToken(req)
		suite.Equal(c.expectation, tokenIsValid, c.message)
		if c.expectation {
			suite.NoError(err)
		} else {
			suite.Error(err)
		}
	}
}

type dummySigningMethod struct{}

func (d dummySigningMethod) Alg() string {
	return "dummy"
}
func (d dummySigningMethod) Verify(signingString, signature string, key interface{}) error {
	return nil
}
func (d dummySigningMethod) Sign(signingString string, key interface{}) (string, error) {
	return "", nil
}
func (suite TokenValidationSuite) TestSigningAlgorithmMismatch() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	m := dummySigningMethod{}
	v := NewWithOptions(Options{
		SigningMethod: m,
		ValidationKeyFunc: func(token *gojwt.Token) (interface{}, error) {
			return genXC5(getModulus(key), exponent)
		},
	})
	token := genToken(key, "http://my-fake-issuer", false)
	req, err := http.NewRequest(http.MethodGet, "http://fake-url-for-test.com", nil)
	suite.NoError(err)
	req.Header.Add("Authorization", token)
	valid, err := v.ValidateBearerToken(req)
	suite.Error(err)
	suite.False(valid)
}

func (suite TokenValidationSuite) TestDefaultValidatorInvalidIssuer() {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vdGVzdGlzc3VlciIsImF1ZCI6Im15YXVkIn0.WUHkFhkN2SJy65jyoLjElNPimBXdehXP5_QeFM40Oh1OvrTEbX4dspzEC8RPcDfQYAjtB5XrODFPiNLRaLAUamYVkmBfbKCE3aRHN7gHOxOGDeZ09GDEjGJ59u9YKrQPIRPLURG9Wg3dFF03c48na61X7Ltn9a_6ICUQzqIsE0rLLCEphmARa75KHYt7TpDTcRiUPj4JSW3ivdxvaMMdQTvI3sgumlNb9VAv8tVPH92-s9mkRRnLiJLaN13Pkz3-0cghQXEqRZVUoVaXTDcZrzLu23as_xG5W8Jz2rFZxUmLVDdKN-wK6L6HFIRM5HFMC3CqWY4RDl3sk4bAiH1ouQ"
	f := GetDefaultValidator(&Options{
		Audience:       "bad",
		VerifyAudience: true,
	})
	res, err := gojwt.Parse(token, f)
	suite.False(res.Valid)
	suite.Error(err)
}

func (suite TokenValidationSuite) TestRequestHasScope() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := genToken(key, issuer, false)
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
			suite.Fail("unable to construct httpRequest for unit test")
		}
		req.Header.Add("Authorization", c.token)

		suite.Equal(c.expectation, RequestHasScope("testscope", req))
	}
}

func (suite TokenValidationSuite) TestGetBearerToken() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := genToken(key, issuer, false)

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
			suite.Fail("unable to construct httpRequest for unit test")
		}
		req.Header.Add("Authorization", c.token)

		token, err := GetBearerToken(req)
		suite.Equal(c.expectation, token)
		if c.expectedError {
			suite.Error(err)
		} else {
			suite.NoError(err)
		}
	}
}

func (suite TokenValidationSuite) TestValidateScope() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := genToken(key, issuer, false)
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
		suite.Equal(c.expectation, ValidateScope(c.testScope, c.token), "expected: %s", c.testScope)
	}
}

func (suite TokenValidationSuite) TestGenXC5() {
	cases := []struct {
		n           string
		e           string
		expectError bool
	}{
		{n: "-", e: "-", expectError: true},
		{n: "AQAB", e: "-", expectError: true},
		{n: "AQAB", e: "AQAB", expectError: false},
	}
	for _, c := range cases {
		_, err := genXC5(c.n, c.e)
		if c.expectError {
			suite.Error(err)
		} else {
			suite.NoError(err)
		}
	}
}
