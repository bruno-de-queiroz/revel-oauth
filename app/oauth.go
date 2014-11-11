package oauth

import (
	"fmt"
	"github.com/creativelikeadog/revel-oauth/app/strategies"
	"github.com/golang/oauth2"
	"github.com/revel/revel"
	"github.com/revel/revel/cache"
	"strings"
)

const (
	SESSION_KEY string = "oauth2"
)

var (
	Providers        = make(map[string]strategies.Strategy)
	providersAllowed = map[string]*ProviderConfig{
		"facebook": &ProviderConfig{"facebook", strategies.FacebookStrategy{}},
		"google":   &ProviderConfig{"google", strategies.DefaultStrategy{}},
	}
)

type ProviderConfig struct {
	Name     string
	Strategy strategies.Strategy
}

func getProvider(s string) (*ProviderConfig, error) {
	if s == "" {
		return nil, fmt.Errorf("No provider informed")
	}
	p := providersAllowed[s]
	if p != nil {
		return p, nil
	}
	return nil, fmt.Errorf("Provider %s not allowed", s)
}

func Init() {

	var i []string

	pc := revel.Config.StringDefault("oauth.provider", "facebook")
	sc := revel.Config.StringDefault("oauth.successUrl", "/")
	ec := revel.Config.StringDefault("oauth.failureUrl", "/")
	ps := strings.Split(pc, ",")

	for _, p := range ps {
		if provider, err := getProvider(p); err == nil {
			if err := appendProvider(provider, sc, ec); err != nil {
				revel.ERROR.Print(err)
			} else {
				i = append(i, p)
			}
		} else {
			revel.WARN.Print(err)
		}
	}

	revel.INFO.Printf("Providers initiated: %s", i)
}

func appendProvider(p *ProviderConfig, s string, e string) error {

	clientId, found := revel.Config.String("oauth." + p.Name + ".clientId")
	if !found {
		return fmt.Errorf("oauth.%s.clientId is missing", p.Name)
	}
	clientSecret, found := revel.Config.String("oauth." + p.Name + ".clientSecret")
	if !found {
		return fmt.Errorf("oauth.%s.clientSecret is missing", p.Name)
	}
	redirectURL, found := revel.Config.String("oauth." + p.Name + ".redirectUrl")
	if !found {
		return fmt.Errorf("oauth.%s.redirectUrl is missing", p.Name)
	}
	scopes, found := revel.Config.String("oauth." + p.Name + ".scopes")
	if !found {
		return fmt.Errorf("oauth.%s.scopes is missing", p.Name)
	}

	sps := strings.Split(scopes, ",")
	surl := revel.Config.StringDefault("oauth."+p.Name+".successUrl", s)
	eurl := revel.Config.StringDefault("oauth."+p.Name+".failureUrl", e)

	pro, err := p.Strategy.New(&oauth2.Options{clientId, clientSecret, redirectURL, sps}, surl, eurl)

	if err != nil {
		return err
	}

	Providers[p.Name] = pro

	return nil
}

func GetUser(c *revel.Controller) (*strategies.UserModel, bool) {
	if value, ok := c.Session[SESSION_KEY]; ok {
		var user *strategies.UserModel
		if err := cache.Get(value, &user); err == nil {
			return user, true
		}
	}
	return nil, false
}

func Login(c *revel.Controller, userData *strategies.UserModel) {
	c.Session[SESSION_KEY] = c.Session.Id()
	go cache.Set(c.Session.Id(), userData, cache.DEFAULT)
}

func Logout(c *revel.Controller) {
	if value, ok := c.Session[SESSION_KEY]; ok {
		go cache.Delete(value)
	}
	for k := range c.Session {
		delete(c.Session, k)
	}
}

func init() {
	revel.OnAppStart(Init)
}
