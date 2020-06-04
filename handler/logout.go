package handler

import (
	"time"

	"github.com/tink-ab/login-service/context"
	"github.com/tink-ab/login-service/settings"
)

type logoutHandler struct {
	appSettings *settings.Settings
}

func NewLogoutHandler(appSettings *settings.Settings) *logoutHandler {
	return &logoutHandler{
		appSettings: appSettings,
	}
}

func (h *logoutHandler) Handle(c context.Context) {
	// Kill all cookies the client allows us to
	for _, cookie := range c.Cookies() {
		cookie.Value = ""
		cookie.Expires = time.Unix(1, 0)
		cookie.Path = "/"
		cookie.Domain = h.appSettings.CookieDomain
		c.SetCookie(cookie)
	}
	c.HTML("logged-out.tmpl", context.H{})
}
