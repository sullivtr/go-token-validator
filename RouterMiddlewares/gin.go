package routermiddlewares

import (
	"github.com/gin-gonic/gin"
	tvm "github.com/tyler-technologies/go-token-validator"
)

// Gin middleware for adding bearer token validation into the request pipeline
func Gin(o tvm.Options) gin.HandlerFunc {
	return func(c *gin.Context) {
		v := tvm.NewRSA256Validator(&o)
		valid, err := v.ValidateBearerToken(c.Request)

		if !valid || err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": err.Error()})
			return
		}
		c.Next()
	}
}
