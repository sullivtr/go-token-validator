package tokenvalidationmiddleware

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

type mockOIDCRequest struct {
	URI  string
	Body interface{}
}

func bodyString(c interface{}) string {
	b, _ := json.Marshal(c)
	return string(b)
}

const (
	validToken   = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVuaXR0ZXN0In0.eyJpc3MiOiJodHRwOi8vZmFrZS1pZHAtaXNzdWVyLyIsInN1YiI6IjBiMTNmODFiLTJjNTctNDkyMS1iNmIyLWE5MTNhOTMwNzcwNyIsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiQmVhcmVyIiwiYXVkIjoiaHR0cDovL2Zha2UtaWRwLWF1ZC8iLCJzY29wZSI6InRlc3RzY29wZSJ9.YRmlows5AaOKwP2q606Cx6l232PrMmTr858msNCo-axFr8ufdJBivgAVb9UFVn9xrbcgKi6Mk81IaAbV3a4L6fB4OUnXg_HYqSdqj_shkKjVm7AFdy3TANyTAKkPz5_5n8ybhzIqW799mOlNPIKXWJJIU3cqefQx4mDiQMQY5xyRAihoLYkaDTS7vUNaCbnAW-UaSu33TDWmt-o-zbLWJfFRIYf74AYh0Mu0M7mwhd1kiFXAwsdzNjZLH_SlLBJfbsNbZs_DEd3UElVFEP-bEOgLpIX3BT92RQE5jwaALm7HPPK6XuGYbKn8Vxc2nq2fVfS_Gv8DJ06qbRh0in35aA"
	expiredToken = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVuaXR0ZXN0In0.eyJpc3MiOiJodHRwOi8vZmFrZS1pZHAtaXNzdWVyLyIsInN1YiI6IjBiMTNmODFiLTJjNTctNDkyMS1iNmIyLWE5MTNhOTMwNzcwNyIsImp0aSI6ImlkMTIzNDU2IiwiZXhwIjoiMTYwMDY0NTI5NSIsImlhdCI6IjE2MDA2NDUyOTUiLCJuYmYiOiIxNjAwNjQ1Mjk1IiwidHlwIjoiQmVhcmVyIiwiYXVkIjoiaHR0cDovL2Zha2UtaWRwLWF1ZC8iLCJzY29wZSI6InRlc3RzY29wZSJ9.A8RJ5U77Bz0FYbDIsDY10V8rTvQQgpJSx8Unaa3HeYV8O8lCU5qZaCzm_IFu1zqkvuC0RQS2Jmqo35-DWHUi1uEqAV1rEAdVhbdF1Inxj_gMIGOR4kUwqot7MDqVb1Fi3iPUU8U-h3xWa6H-KnXo_aIiAG34balvVK8GBLQTuaH7CeXfuQuukoAeErIgdlIC-blAq493JElK6hlDir_8mN2WydyZSvoUpwr1TY0omWsKAEUg-VFCTB9rBCWPc2bG2V5fGnRsZeKkvdki3iTAE_kj2jAxMtEGlD7a2xnOgatuqog2lVySMNNnW-N5kfCbwqCJoiqjTMCMjm8shvYHjA"
	modulus      = "hzz_cV2bPPoMVLShldvHJr6q6H7ieEEfQ3EnWJ89w3-3GzDxKSTdDk0MwbXBaLQKbp6_y7P4jAfV3JAfWRm8xk0ySqar9dDPBxFrFYKBZEM7uQjsEZxs-NC9p7TvbqTB4oxXKD3O09iG4P-L7Ne3gZsM2OETyApPjx7av7slKRhtI_dLskM3SzjMc27KVKv0_eJ41LAfY5bNrhZDegmhkCuna_KPRYx98eL9c009_GB0LC720xTNZiFkc6a9jpLNEY-VcBSlinG1kPqRVToicfEcSUvBE8j3VTjhsRZB1qsW_BCEZw62Si_1dMUJSWD1twz07anxVV6EMmWR5-zY0w"
	exponent     = "AQAB"
	issuer       = "http://fake-idp-issuer/"
	audience     = "http://fake-idp-aud/"
	jwksURI      = "http://fake-idp-issuer/jwks/"
	kid          = "unittest"
)

var (
	jwksURIReqValid = mockOIDCRequest{
		URI: "http://fake-idp-issuer/.well-known/openid-configuration",
		Body: OpenIDConfig{
			JwksURI: jwksURI,
		},
	}

	jwksReqValid = mockOIDCRequest{
		URI: jwksURI,
		Body: Jwks{
			Keys: []JSONWebKeys{
				JSONWebKeys{
					N:   modulus,
					E:   exponent,
					Kid: kid,
				},
			},
		},
	}

	jwksReqInvalid = mockOIDCRequest{
		URI: jwksURI,
		Body: Jwks{
			Keys: []JSONWebKeys{
				JSONWebKeys{
					N:   "bad-mod",
					E:   "bad-exponent",
					Kid: kid,
				},
			},
		},
	}
)

func TestNew(t *testing.T) {
	v := New()
	assert.NotNil(t, v)
	assert.NotNil(t, v.Options)
}

func TestNewRSA256ValidatorNoJwks(t *testing.T) {
	httpmock.ActivateNonDefault(httpClient)
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("GET", jwksReqInvalid.URI, httpmock.NewJsonResponderOrPanic(200, jwksReqInvalid.Body))

	v := NewRSA256Validator(&Options{
		Audience:       audience,
		Issuer:         issuer,
		VerifyAudience: true,
		VerifyIssuer:   true,
	})
	assert.NotNil(t, v)
	req, err := http.NewRequest(http.MethodGet, "http://fake-url-for-test.com", nil)
	assert.NoError(t, err)

	req.Header.Add("Authorization", validToken)
	tokenIsValid, err := v.ValidateBearerToken(req)
	assert.Error(t, err)
	assert.False(t, tokenIsValid)
}

func TestNewRSA256Validator(t *testing.T) {
	cases := []struct {
		token       string
		issuer      string
		audience    string
		expectation bool
	}{
		{token: validToken, issuer: issuer, audience: audience, expectation: true},
		// {token: expiredToken, issuer: issuer, audience: audience, expectation: false}, // Need to look into this. This token is expired (I think) so it should fail.
		{token: "invalidtoken", issuer: issuer, audience: audience, expectation: false},
		{token: "", issuer: issuer, audience: audience, expectation: false},
		{token: validToken, issuer: "invalidissuer", audience: audience, expectation: false},
		{token: validToken, issuer: issuer, audience: "invalidaudience", expectation: false},
	}

	for _, c := range cases {
		httpmock.ActivateNonDefault(httpClient)
		defer httpmock.DeactivateAndReset()
		httpmock.RegisterResponder("GET", jwksURIReqValid.URI, httpmock.NewJsonResponderOrPanic(200, jwksURIReqValid.Body))
		httpmock.RegisterResponder("GET", jwksReqValid.URI, httpmock.NewJsonResponderOrPanic(200, jwksReqValid.Body))

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
		assert.Equal(t, c.expectation, tokenIsValid)
	}
}

func TestRequestHasScope(t *testing.T) {
	cases := []struct {
		token       string
		testScope   string
		expectation bool
	}{
		{token: validToken, testScope: "testscope", expectation: true},
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
	cases := []struct {
		token         string
		testScope     string
		expectation   string
		expectedError bool
	}{
		{token: validToken, testScope: "testscope", expectation: strings.Replace(validToken, "Bearer ", "", 1), expectedError: false},
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
	cases := []struct {
		token       string
		testScope   string
		expectation bool
	}{
		{token: strings.Replace(validToken, "Bearer ", "", 1), testScope: "testscope", expectation: true},
		{token: strings.Replace(validToken, "Bearer ", "", 1), testScope: "missingscope", expectation: false},
		{token: "", testScope: "testscope", expectation: false},
	}

	for _, c := range cases {
		assert.Equal(t, c.expectation, ValidateScope(c.testScope, c.token), "expected: %s", c.testScope)
	}
}
