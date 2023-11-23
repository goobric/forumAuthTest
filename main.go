package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/gin-gonic/gin"
)

var (
	googleOauthConfig = &oauth2.Config{
		ClientID:     "your-google-client-id",
		ClientSecret: "your-google-client-secret",
		RedirectURL:  "http://localhost:8000/auth/google/callback",
		Scopes:       []string{"profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://accounts.google.com/o/oauth2/token",
		},
	}

	githubOauthConfig = &oauth2.Config{
		ClientID:     "your-github-client-id",
		ClientSecret: "your-github-client-secret",
		RedirectURL:  "http://localhost:8000/auth/github/callback",
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
)

func main() {
	r := gin.Default()

	r.LoadHTMLGlob("templates/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", nil)
	})

	r.GET("/auth/google/login", func(c *gin.Context) {
		state := "google"
		url := googleOauthConfig.AuthCodeURL(state)
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	r.GET("/auth/github/login", func(c *gin.Context) {
		state := "github"
		url := githubOauthConfig.AuthCodeURL(state)
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	r.GET("/auth/google/callback", handleCallback)
	r.GET("/auth/github/callback", handleCallback)

	r.Run(":8000")
}

func handleCallback(c *gin.Context) {
	ctx := context.Background()
	code := c.Query("code")
	state := c.Query("state")
	token, err := exchangeToken(ctx, code, state)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange token")
		return
	}

	user, err := getUserInfo(ctx, token, state)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to get user info")
		return
	}

	c.String(http.StatusOK, fmt.Sprintf("Hello there, %s!", user.Name))
}

// Add state parameter
func exchangeToken(ctx context.Context, code string, state string) (*oauth2.Token, error) {
	switch state {
	case "google":
		return googleOauthConfig.Exchange(ctx, code)
	case "github":
		return githubOauthConfig.Exchange(ctx, code)
	default:
		return nil, fmt.Errorf("invalid OAuth state")
	}
}

// Add state parameter
func getUserInfo(ctx context.Context, token *oauth2.Token, state string) (*UserInfo, error) {
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

	resp, err := client.Get("https://www.google.com/")
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

	resp, err := client.Get("https://github.com/login")
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
