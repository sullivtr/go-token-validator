package routermiddlewares

import (
	"github.com/labstack/echo/v4"
	tvm "github.com/tyler-technologies/go-token-validator"
)

// Echo middleware for adding bearer token validation into the request pipeline
func Echo(o tvm.Options) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			v := tvm.NewRSA256Validator(&o)
			valid, err := v.ValidateBearerToken(c.Request())

			if !valid || err != nil {
				return echo.ErrUnauthorized
			}
			return next(c)
		}
	}
}
