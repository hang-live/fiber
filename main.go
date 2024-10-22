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

type SignupRequest struct {
	Email string
	Password string
}

var allowList = map[string]bool{
    "http://localhost:3000": true,
    "https://hanglive.com":  true,
}

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
		if origin := c.Request.Header.Get("Origin"); allowList[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		// Handle preflight OPTIONS request
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		var loginRequest authorizer.LoginInput
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
			Email:    loginRequest.Email,
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
		AllowOrigins:     []string{"http://localhost:3000", "https://hanglive.com"},
		AllowMethods:     []string{http.MethodGet, http.MethodPatch, http.MethodPost, http.MethodHead, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{"Content-Type", "X-XSRF-TOKEN", "Accept", "Origin", "X-Requested-With", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	router.POST("/signup", func(c *gin.Context) {
		// Set CORS headers
		if origin := c.Request.Header.Get("Origin"); allowList[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		// Handle preflight OPTIONS request
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		var signUpRequest authorizer.SignUpInput
		if err := c.ShouldBindJSON(&signUpRequest); err != nil {
			log.Println("error binding sign up request: ", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		client, err := authorizer.NewAuthorizerClient(os.Getenv("AUTHORIZER_CLIENT_ID"), os.Getenv("AUTHORIZER_URL"), os.Getenv("AUTHORIZER_REDIRECT_URL"), nil)
		if err != nil {
			log.Println("error creating authorizer client: ", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	
		res, err := client.SignUp(&authorizer.SignUpInput{
			Email:    signUpRequest.Email,
			Password: signUpRequest.Password,
			ConfirmPassword: signUpRequest.ConfirmPassword,
		})
		if err != nil {
			log.Println("error signing up: ", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": authorizer.StringValue(res.Message),
		})
		return
	}).Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "https://hanglive.com"},
		AllowMethods:     []string{http.MethodGet, http.MethodPatch, http.MethodPost, http.MethodHead, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{"Content-Type", "X-XSRF-TOKEN", "Accept", "Origin", "X-Requested-With", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	router.POST("/forgot-password", func(c *gin.Context) {
		// Set CORS headers
		if origin := c.Request.Header.Get("Origin"); allowList[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		// Handle preflight OPTIONS request
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		var forgotPasswordRequest struct {
			Email string `json:"email" binding:"required,email"`
		}
		if err := c.ShouldBindJSON(&forgotPasswordRequest); err != nil {
			log.Println("error binding forgot password request: ", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		client, err := authorizer.NewAuthorizerClient(os.Getenv("AUTHORIZER_CLIENT_ID"), os.Getenv("AUTHORIZER_URL"), os.Getenv("AUTHORIZER_REDIRECT_URL"), nil)
		if err != nil {
			log.Println("error creating authorizer client: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
	
		res, err := client.ForgotPassword(&authorizer.ForgotPasswordInput{
			Email: forgotPasswordRequest.Email,
		})
		if err != nil {
			log.Println("error in forgot password: ", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": authorizer.StringValue(&res.Message),
		})
	}).Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "https://hanglive.com"},
		AllowMethods:     []string{http.MethodGet, http.MethodPatch, http.MethodPost, http.MethodHead, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{"Content-Type", "X-XSRF-TOKEN", "Accept", "Origin", "X-Requested-With", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))
 
	router.Run(getPort())
}
