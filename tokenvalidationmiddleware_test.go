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

func (suite TokenValidationSuite) TestDefaultValidator() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		issuer        string
		options       Options
		bearer        string
		wkeResponder  httpmock.Responder
		jwksResponder httpmock.Responder
		shouldErr     bool
	}{
		{
			issuer:        "http://validissuer/",
			options:       Options{VerifyIssuer: true, VerifyAudience: true, Issuer: "http://validissuer/", Audience: audience},
			bearer:        genToken(key, "http://validissuer/", false),
			wkeResponder:  httpmock.NewJsonResponderOrPanic(200, OpenIDConfig{JwksURI: "http://validissuer/"}),
			jwksResponder: httpmock.NewJsonResponderOrPanic(200, Jwks{Keys: []JSONWebKeys{{N: getModulus(key), E: exponent, Kid: "unittest"}}}),
			shouldErr:     false,
		},
		{
			issuer:        "http://invalidaudience/",
			options:       Options{VerifyIssuer: true, VerifyAudience: true, Issuer: "http://invalidaudience/", Audience: "wrongaud"},
			bearer:        genToken(key, "http://invalidaudience/", false),
			wkeResponder:  nil,
			jwksResponder: nil,
			shouldErr:     true,
		},
		{
			issuer:        "http://invalidissuer/",
			options:       Options{VerifyIssuer: true, VerifyAudience: true, Issuer: "http://wrongissuer/", Audience: audience},
			bearer:        genToken(key, "http://invalidissuer/", false),
			wkeResponder:  nil,
			jwksResponder: nil,
			shouldErr:     true,
		},
		{
			issuer:        "http://invalidpemcert/",
			options:       Options{VerifyIssuer: true, VerifyAudience: true, Issuer: "http://invalidpemcert/", Audience: audience},
			bearer:        genToken(key, "http://invalidpemcert/", false),
			wkeResponder:  httpmock.NewErrorResponder(errors.New("error")),
			jwksResponder: nil,
			shouldErr:     true,
		},
	}

	for _, c := range cases {
		httpmock.ActivateNonDefault(httpClient)
		if c.wkeResponder != nil {
			httpmock.RegisterResponder("GET", c.issuer+".well-known/openid-configuration", c.wkeResponder)
		}
		if c.jwksResponder != nil {
			httpmock.RegisterResponder("GET", c.issuer, c.jwksResponder)
		}

		f := GetDefaultValidator(&c.options)
		token := strings.Replace(c.bearer, "Bearer ", "", 1)
		t, _, err := new(gojwt.Parser).ParseUnverified(token, gojwt.MapClaims{})
		suite.NoError(err)
		_, err = f(t)
		httpmock.DeactivateAndReset()
		if c.shouldErr {
			suite.Error(err)
		} else {
			suite.NoError(err)
		}
	}
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

func (suite TokenValidationSuite) TestNewRSA256Validator() {
	m := NewRSA256Validator(&Options{VerifyIssuer: true, VerifyAudience: true, Issuer: "http://validissuer/", Audience: audience})
	suite.NotNil(m)
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

func (suite TokenValidationSuite) TestValidateBearerToken() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		middleware *TokenValidationMiddleware
		bearer     string
		valid      bool
	}{
		{
			middleware: New(),
			bearer:     "",
			valid:      false,
		},
		{
			middleware: NewWithOptions(Options{
				ValidationKeyFunc: func(token *gojwt.Token) (interface{}, error) { return "", errors.New("error") },
			}),
			bearer: genToken(key, "http://my-fake-issuer", false),
			valid:  false,
		},
		{
			middleware: NewWithOptions(Options{
				SigningMethod: dummySigningMethod{},
				ValidationKeyFunc: func(token *gojwt.Token) (interface{}, error) {
					return genXC5(getModulus(key), exponent)
				},
			}),
			bearer: genToken(key, "http://my-fake-issuer", false),
			valid:  false,
		},
		{
			middleware: NewWithOptions(Options{
				ValidationKeyFunc: func(token *gojwt.Token) (interface{}, error) {
					return genXC5(getModulus(key), exponent)
				},
			}),
			bearer: genToken(key, "http://my-fake-issuer", false),
			valid:  true,
		},
	}

	for _, c := range cases {
		req, err := http.NewRequest(http.MethodGet, "http://fake-url-for-test.com", nil)
		suite.NoError(err)
		req.Header.Add("Authorization", c.bearer)
		valid, err := c.middleware.ValidateBearerToken(req)
		if c.valid {
			suite.NoError(err)
			suite.True(valid)
		} else {
			suite.Error(err)
			suite.False(valid)
		}
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

func (suite TokenValidationSuite) TestGetPemCert() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		issuer        string
		wkeResponder  httpmock.Responder
		jwksResponder httpmock.Responder
		shouldErr     bool
	}{
		{
			issuer:        "http://test/",
			wkeResponder:  httpmock.NewJsonResponderOrPanic(200, OpenIDConfig{JwksURI: "http://test/"}),
			jwksResponder: httpmock.NewJsonResponderOrPanic(200, Jwks{Keys: []JSONWebKeys{{N: getModulus(key), E: exponent, Kid: "unittest"}}}),
			shouldErr:     false,
		},
		{
			issuer:        "http://errorissuer/",
			wkeResponder:  httpmock.NewErrorResponder(errors.New("error")),
			jwksResponder: nil,
			shouldErr:     true,
		},
		{
			issuer:        "http://invalidjsonwke/",
			wkeResponder:  httpmock.NewStringResponder(200, "{invalidjsonwke}"),
			jwksResponder: nil,
			shouldErr:     true,
		},
		{
			issuer:        "http://invalidjsonjwks/",
			wkeResponder:  httpmock.NewJsonResponderOrPanic(200, OpenIDConfig{JwksURI: "http://invalidjsonjwks/"}),
			jwksResponder: httpmock.NewStringResponder(200, "{invalidjsonjwks}"),
			shouldErr:     true,
		},
		{
			issuer:        "http://errorjwks/",
			wkeResponder:  httpmock.NewJsonResponderOrPanic(200, OpenIDConfig{JwksURI: "http://errorjwks/"}),
			jwksResponder: httpmock.NewErrorResponder(errors.New("error")),
			shouldErr:     true,
		},
		{
			issuer:        "http://missingkeys/",
			wkeResponder:  httpmock.NewJsonResponderOrPanic(200, OpenIDConfig{JwksURI: "http://missingkeys/"}),
			jwksResponder: httpmock.NewJsonResponderOrPanic(200, Jwks{Keys: []JSONWebKeys{{E: exponent, Kid: "unittest"}}}),
			shouldErr:     true,
		},
		{
			issuer:        "http://invalidXC5/",
			wkeResponder:  httpmock.NewJsonResponderOrPanic(200, OpenIDConfig{JwksURI: "http://invalidXC5/"}),
			jwksResponder: httpmock.NewJsonResponderOrPanic(200, Jwks{Keys: []JSONWebKeys{{N: "-", E: "-", Kid: "unittest"}}}),
			shouldErr:     true,
		},
	}

	for _, c := range cases {
		token := genToken(key, c.issuer, false)
		httpmock.ActivateNonDefault(httpClient)
		if c.wkeResponder != nil {
			httpmock.RegisterResponder("GET", c.issuer+".well-known/openid-configuration", c.wkeResponder)
		}
		if c.jwksResponder != nil {
			httpmock.RegisterResponder("GET", c.issuer, c.jwksResponder)
		}
		token = strings.Replace(token, "Bearer ", "", 1)
		t, _, err := new(gojwt.Parser).ParseUnverified(token, gojwt.MapClaims{})
		suite.NoError(err)

		_, err = getPemCert(t, c.issuer)
		httpmock.DeactivateAndReset()
		if c.shouldErr {
			suite.Error(err)
		} else {
			suite.NoError(err)
		}
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
