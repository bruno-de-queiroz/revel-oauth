package strategies

import (
	"fmt"
	"github.com/golang/oauth2"
)

type DefaultStrategy struct {
	config     *oauth2.Config
	baseURL    string
	successURL string
	failureURL string
}

func (p DefaultStrategy) New(opts *oauth2.Options, s string, f string) (Strategy, error) {

	b := "https://accounts.google.com"
	a := b + "/o/oauth2/auth"
	t := b + "/o/oauth2/token"

	if c, err := oauth2.NewConfig(opts, a, t); err != nil {
		return nil, err
	} else {
		return &DefaultStrategy{c, b, s, f}, nil
	}
}

func (p DefaultStrategy) Config() *oauth2.Config {
	return p.config
}

func (p DefaultStrategy) OnSuccess() string {
	return p.successURL
}

func (p DefaultStrategy) BaseURL() string {
	return p.baseURL
}

func (p DefaultStrategy) OnFailure() string {
	return p.failureURL
}

func (p DefaultStrategy) Authorize(code string) (*UserModel, error) {

	fmt.Println("Authorizing in default")

	t, err := p.Config().Exchange(code)
	if err != nil {
		return nil, err
	}

	d := &UserModel{}
	d.AccessToken = t
	d.Provider = "default"

	return d, nil
}
