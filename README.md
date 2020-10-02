# Go-Token-Validator

This package provides automatic `RS256` based JWT token validation by verifying claims, and validating signing keys with token issuer.

## Why use go-token-validator?
- Go beyond simple claims verification by verifying bearer token signing keys with your token issuer on the fly.
- Add token validation middleware to any Go http router with little configuration.
- Secure your Go REST APIs with any identity provider with bearer token authentication.


## Usage example

### Using middleware
 This example spins up a simple http server using the included default Gin token validation middleware:
```golang
import (
  tv "github.com/tyler-technologies/go-token-validator"
)

func main() {
	r := gin.Default()

	vo := tv.Options{
		Issuer:         "https://your-issuer-url/",
		Audience:       "exampleaudience",
		VerifyAudience: false,
		VerifyIssuer:   true,
  }
  
	r.Use(tv.RouterMiddlewares.Gin(&vo))

	r.GET("/", func(c *gin.Context) {
		authHeaderParts := strings.Split(c.Request.Header.Get("Authorization"), " ")
		token := authHeaderParts[1]
		hasScope := tv.ValidateScope("TestScope", token)

		if !hasScope {
			message := "Insufficient scope."
			c.JSON(http.StatusForbidden, message)
			return
		}
		message := "Hello from a private endpoint! You need to be authenticated to see this."
		c.JSON(http.StatusOK, message)
	})

	r.Run(":8080")
}
```

### Building custom middleware func for a specific router: (Example using Gin Router)
Example implementing RSA256 validation func using gin middleware: 
```go
// Gin middleware for adding bearer token validation into the request pipeline
func Gin(o tvm.Options) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create an instance of the RSA256Validation middleware
		v := tvm.NewRSA256Validator(&o)
		// Validate Bearer token from the request (Usage of this in middleware makes the assumption that authentication is required)
		valid, err := v.ValidateBearerToken(c.Request)

		if !valid || err != nil  {
			c.AbortWithStatusJSON(401, gin.H{"error": err.Error()})
			return
		}
		c.Next()
	}
}
```


