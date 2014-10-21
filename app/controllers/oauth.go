package controllers

import (
	"github.com/creativelikeadog/revel-oauth/app"
	"github.com/creativelikeadog/revel-oauth/app/strategies"
	"github.com/revel/revel"
)

type OAuth struct {
	*revel.Controller
	provider strategies.Strategy
}

func (c *OAuth) Auth(code string) revel.Result {
	if code == "" {
		return c.Redirect(c.provider.OnFailure())
	}

	if user, err := c.provider.Authorize(code); err != nil {
		c.Flash.Error(err.Error())
		return c.Redirect(c.provider.OnFailure())
	} else {
		oauth.Login(c.Controller, user)
		return c.Redirect(c.provider.OnSuccess())
	}

	return c.Redirect(c.provider.OnFailure())
}

func (c *OAuth) Logout() revel.Result {
	oauth.Logout(c.Controller)
	return c.Redirect(c.provider.OnFailure())
}

func (c *OAuth) Provider() revel.Result {
	p := c.Params.Get("provider")
	cfg := oauth.Providers[p]
	if cfg != nil {
		c.provider = cfg
		return nil
	}

	return c.NotFound("Not found")
}

func init() {
	revel.InterceptMethod((*OAuth).Provider, revel.BEFORE)
}
