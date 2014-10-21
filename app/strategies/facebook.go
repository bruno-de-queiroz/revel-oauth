package strategies

import (
	"encoding/json"
	"fmt"
	"github.com/golang/oauth2"
	"io/ioutil"
	"net/http"
)

type FacebookStrategy struct {
	config     *oauth2.Config
	baseURL    string
	successURL string
	failureURL string
}

func (p FacebookStrategy) New(opts *oauth2.Options, s string, f string) (Strategy, error) {
	b := "https://graph.facebook.com"
	a := b + "/oauth/authorize"
	t := b + "/oauth/access_token"

	if c, err := oauth2.NewConfig(opts, a, t); err != nil {
		return nil, err
	} else {
		return &FacebookStrategy{c, b, s, f}, nil
	}
}

func (p FacebookStrategy) Config() *oauth2.Config {
	return p.config
}

func (p FacebookStrategy) BaseURL() string {
	return p.baseURL
}

func (p FacebookStrategy) OnSuccess() string {
	return p.successURL
}

func (p FacebookStrategy) OnFailure() string {
	return p.failureURL
}
func (p FacebookStrategy) Authorize(code string) (*UserModel, error) {

	fmt.Println("Authorizing in facebook")

	t, err := p.Config().Exchange(code)
	if err != nil {
		return nil, err
	}

	url := p.BaseURL() + "/me?access_token=" + t.AccessToken

	if p.Config().Client == nil {
		p.Config().Client = http.DefaultClient
	}

	r, err := p.Config().Client.Get(url)
	if err != nil {
		return nil, err
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch user data: %v", err)
	}

	if c := r.StatusCode; c < 200 || c > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch user data: %v\nResponse: %s", r.Status, body)
	}

	resp := &UserModel{}

	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	resp.Raw = string(body[:])
	resp.AccessToken = t
	resp.Provider = "facebook"

	return resp, nil
}
