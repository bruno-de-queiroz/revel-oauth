package oauth

import (
	"fmt"
	"github.com/creativelikeadog/revel-oauth/app/strategies"
	"github.com/golang/oauth2"
	"github.com/revel/revel"
	"strings"
)

const (
	SESSION_KEY          string = "oauth2"
	SESSION_KEY_PROVIDER string = SESSION_KEY + "_provider"
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

func getUser(c *revel.Controller) (bool, interface{}) {
	if value, ok := c.Session[SESSION_KEY]; ok {
		if v, ok := c.Session[SESSION_KEY_PROVIDER]; ok {
			return true, struct{ UserId, Provider string }{value, v}
		} else {
			return false, nil
		}
	}
	return false, nil
}

func Login(c *revel.Controller, userData *strategies.UserModel) {
	c.Session[SESSION_KEY] = userData.Id
	c.Session[SESSION_KEY_PROVIDER] = userData.Provider
	c.Session.SetDefaultExpiration()
}

func Logout(c *revel.Controller) {
	for k := range c.Session {
		delete(c.Session, k)
	}
}

type OAuthInterceptor struct {
	*revel.Controller
	UserData interface{}
	Redir    string
}

func (c *OAuthInterceptor) Middleware() revel.Result {
	if authorized, data := getUser(c.Controller); authorized == true {
		c.UserData = data
		return nil
	} else {
		return c.Forbidden("You need to login")
	}
	return nil
}

func init() {
	revel.OnAppStart(Init)
	revel.InterceptMethod((*OAuthInterceptor).Middleware, revel.BEFORE)
}
