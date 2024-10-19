package main

import (
	"os"
	"net/http"
	"strings"
	"log"
 
	"github.com/authorizerdev/authorizer-go"
	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"github.com/joho/godotenv"
)

type LoginRequest struct {
	Email string
	Password string
}

var Origins = []string{"http://localhost:3000"}

func AuthorizeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		env := os.Getenv("ENV")
		if env == "local" {
			c.Next()
			return
		}
		
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

func main() {
	err := godotenv.Load()
	if err != nil {
	  log.Fatal("Error loading .env file")
	}

	router := gin.New()
 
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	}).Use(AuthorizeMiddleware())

	router.POST("/login", func(c *gin.Context) {
		// Set CORS headers
		c.Header("Access-Control-Allow-Origin", "http://localhost:3000")

		// Handle preflight OPTIONS request
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		var loginRequest LoginRequest
		if err := c.ShouldBindJSON(&loginRequest); err != nil {
			log.Println("error binding login request: ", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		client, err := authorizer.NewAuthorizerClient(os.Getenv("AUTHORIZER_CLIENT_ID"), os.Getenv("AUTHORIZER_URL"), os.Getenv("AUTHORIZER_REDIRECT_URL"), nil)
		if err != nil {
			log.Println("error creating authorizer client: ", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	
		res, err := client.Login(&authorizer.LoginInput{
			Email:    &loginRequest.Email,
			Password: loginRequest.Password,
		})
		if err != nil {
			log.Println("error logging in: ", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	
		c.JSON(http.StatusOK, gin.H{
			"message": authorizer.StringValue(res.Message),
			"token": authorizer.StringValue(res.AccessToken),
		})
		return
	}).Use(cors.New(cors.Config{
		AllowOrigins:     []string{os.Getenv("FRONTEND_URL"), "http://localhost:3000"},
		AllowMethods:     []string{http.MethodGet, http.MethodPatch, http.MethodPost, http.MethodHead, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{"Content-Type", "X-XSRF-TOKEN", "Accept", "Origin", "X-Requested-With", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			for _, o := range Origins {
				if o == origin {
					return true
				}
			}
			return false
		  },
	}))
 
	router.Run(getPort())
}
