package tokenvalidationmiddleware

import (
	"errors"
	"net/http"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

const (
	testToken = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVuaXR0ZXN0In0.eyJpc3MiOiJodHRwOi8vZmFrZS1pZHAtaXNzdWVyLyIsInN1YiI6IjBiMTNmODFiLTJjNTctNDkyMS1iNmIyLWE5MTNhOTMwNzcwNyIsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiQmVhcmVyIiwiYXVkIjoiaHR0cDovL2Zha2UtaWRwLWF1ZC8iLCJzY29wZSI6InRlc3RzY29wZSJ9.QCBVG1K8Nd0J3gKcwIABNrW75CpJApKw9OuhEcP-znn_rpkF49dURYxyYzlYqvLMi_MFM0yngcryMZwVdOo5-EIpOuS3f2rdRIhws4_ynPeyqUhhplR-mZVljm4BAbtjevnjsYh7p_0ia-TKbotDaODDeBJDKR1mvJIDtrqRkhI17uJ_sqNh05tRILk3nZkZf6v1ARmfK8A4z1OTIF3If5NCDa63AJF42ZvnfwuNN1o3fucmrXxOAtARp-3AT6qQ_2nuZwsZq_2Wt3nr_cl5DPIESwzrGabT_-owI-TSLbfu7m_67gvfeL6XW17oKK6xtTVJUvIMRobLkYN5yBMeNg"
	modulus   = "qs6HgNBcDw37GfursjEnTqmgbfA1Drx7tzxny59_dxA4E227bldtRqY9qHJIGw5d6i3-UMTxYdADunzIIjSTIOwTs47erTIuUpWC-Be5PwvI_GTHh9nTQRKiQmBfKHrI2JcrFbRiLwmLy6fAFrfwSLxE3d0_SwEp4Nk5xvwiOQGT5VnfwdJboSLwcax3JiGhx3lg8gGpB-7C7j4dEnYuBlvT0QxGZ8aOMd5mVWlpmfookToJ00uL1ZF2HFhYqYcHTaY4yXRazl18pEJ_so2CX_pVq4fo1libV4rq9ldKAl1BwtRiS4v4HanaDAbzKPGThj6n2rFl3y0x6ymudel7Ew"
	exponent  = "AQAB"
)

func TestValidateBearerTokenIsSuccess(t *testing.T) {
	mw := newDefaultMockMiddleware()

	assert.Equal(t, mw.Options.Issuer, "http://fake-idp-issuer/")
	assert.Equal(t, mw.Options.Audience, "http://fake-idp-aud/")

	req, err := http.NewRequest(http.MethodGet, "http://fake-url-for-test.com", nil)
	if err != nil {
		assert.Fail(t, "unable to construct httpRequest for unit test")
	}

	req.Header.Add("Authorization", testToken)
	tokenIsValid, err := mw.ValidateBearerToken(req)

	assert.Nil(t, err)
	assert.True(t, tokenIsValid)
}

func newDefaultMockMiddleware() *TokenValidationMiddleware {
	aud := "http://fake-idp-aud/"
	iss := "http://fake-idp-issuer/"
	return New(Options{
		VerifyIssuer:   true,
		VerifyAudience: true,
		Issuer:         iss,
		Audience:       aud,
		ValidationKeyFunc: func(token *jwt.Token) (interface{}, error) {
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
			if !checkAud {
				return token, errors.New("Invalid audience")
			}
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, true)
			if !checkIss {
				return token, errors.New("Invalid issuer")
			}
			cert, err := getPemCert(token, iss, modulus, exponent)
			if err != nil {
				panic(err.Error())
			}
			return cert, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})
}
