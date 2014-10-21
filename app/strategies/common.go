package strategies

import (
	"github.com/golang/oauth2"
)

type Strategy interface {
	New(opts *oauth2.Options, s string, f string) (Strategy, error)
	Config() *oauth2.Config
	Authorize(c string) (*UserModel, error)
	BaseURL() string
	OnSuccess() string
	OnFailure() string
}

type UserModel struct {
	Id          string        `json:"id"`
	Username    string        `json:"username"`
	Name        string        `json:"name"`
	Email       string        `json:"email"`
	AccessToken *oauth2.Token `json:"_token"`
	Raw         interface{}   `json:"_raw"`
	Provider    string        `json:"provider"`
}
