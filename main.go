package main

import (
	"os"
	"net/http"
	"strings"
	"log"
 
	"github.com/authorizerdev/authorizer-go"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func AuthorizeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		env := os.Getenv("ENV")
		if env == "local" {
			c.Next()
			return
		}

		/**
		  for open routes you can add condition here and just return with c.Next()
		  so that it does not validate token for those routes
		*/
		authHeader := c.Request.Header.Get("Authorization")
		tokenSplit := strings.Split(authHeader, " ")
 
		defaultHeaders := map[string]string{}
		authorizerClient, err := authorizer.NewAuthorizerClient(os.Getenv("AUTHORIZER_CLIENT_ID"), os.Getenv("AUTHORIZER_URL"), os.Getenv("AUTHORIZER_REDIRECT_URL"), defaultHeaders)
		if err != nil {
			// unauthorized
			c.AbortWithStatusJSON(401, "unauthorized")
			log.Println("unauthorized authorizer client: ", err)
			return
		}
 
		if len(tokenSplit) < 2 || tokenSplit[1] == "" {
			// unauthorized
			c.AbortWithStatusJSON(401, "unauthorized")
			log.Println("unauthorized token split: ", tokenSplit[1], tokenSplit)
			return
		}
 
		res, err := authorizerClient.ValidateJWTToken(&authorizer.ValidateJWTTokenInput{
			TokenType: authorizer.TokenTypeIDToken,
			Token:     tokenSplit[1],
		})
		if err != nil {
			// unauthorized
			c.AbortWithStatusJSON(401, "unauthorized")
			log.Println("unauthorized JWT validation: ", err)
			return
		}
 
		if !res.IsValid {
			// unauthorized
			c.AbortWithStatusJSON(401, "unauthorized")
			log.Println("unauthorized, invalid response: ", res.IsValid)
			return
		}
 
		c.Next()
	}
}

func getPort() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = ":3000"
	} else {
		port = ":" + port
	}

	return port
}

// func main() {
// 	app := fiber.New()

// 	app.Get("/", func(c *fiber.Ctx) error {
// 		return c.JSON(fiber.Map{
// 			"message": "Hello, Railway!",
// 		})
// 	})

// 	app.Listen(getPort())
// }

func main() {
	err := godotenv.Load()
	if err != nil {
	  log.Fatal("Error loading .env file")
	}

	router := gin.New()
	router.Use(AuthorizeMiddleware())
 
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
 
	router.Run(getPort())
}
