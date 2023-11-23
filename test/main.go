package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/gin-gonic/gin"
)

var (
	googleOauthConfig = &oauth2.Config{
		ClientID:     "your-google-client-id",
		ClientSecret: "your-google-client-secret",
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		Scopes:       []string{"profile", "email"},
		Endpoint:     google.Endpoint, //oauth2.GoogleEndpoint,
	}

	githubOauthConfig = &oauth2.Config{
		ClientID:     "your-github-client-id",
		ClientSecret: "your-github-client-secret",
		RedirectURL:  "http://localhost:8080/auth/github/callback",
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}

	state string
)

func main() {
	r := gin.Default()

	r.LoadHTMLGlob("templates/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", nil)
	})

	r.GET("/auth/google/login", func(c *gin.Context) {
		state = "google"
		url := googleOauthConfig.AuthCodeURL(state)
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	r.GET("/auth/github/login", func(c *gin.Context) {
		state = "github"
		url := githubOauthConfig.AuthCodeURL(state)
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	r.GET("/auth/google/callback", handleCallback)
	r.GET("/auth/github/callback", handleCallback)

	r.Run(":8080")
}

func handleCallback(c *gin.Context) {
	ctx := context.Background()
	code := c.Query("code")
	token, err := exchangeToken(ctx, code)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange token")
		return
	}

	user, err := getUserInfo(ctx, token)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to get user info")
		return
	}

	c.String(http.StatusOK, fmt.Sprintf("Hello, %s!", user.Name))
}

func exchangeToken(ctx context.Context, code string) (*oauth2.Token, error) {
	switch state {
	case "google":
		return googleOauthConfig.Exchange(ctx, code)
	case "github":
		return githubOauthConfig.Exchange(ctx, code)
	default:
		return nil, fmt.Errorf("invalid OAuth state")
	}
}

func getUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	switch state {
	case "google":
		return getGoogleUserInfo(ctx, token)
	case "github":
		return getGitHubUserInfo(ctx, token)
	default:
		return nil, fmt.Errorf("invalid OAuth state")
	}
}

type UserInfo struct {
	ID    string
	Name  string
	Email string
}

func getGoogleUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := googleOauthConfig.Client(ctx, token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user UserInfo
	if err := decodeJSON(resp.Body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func getGitHubUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := githubOauthConfig.Client(ctx, token)

	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user UserInfo
	if err := decodeJSON(resp.Body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func decodeJSON(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}