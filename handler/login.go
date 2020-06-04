package handler

import (
	"net/http"

	"github.com/pkg/errors"

	"github.com/tink-ab/login-service/context"
	"github.com/tink-ab/login-service/provider"
	"github.com/tink-ab/login-service/session"
	"github.com/tink-ab/login-service/settings"
)

type loginHandler struct {
	appSettings *settings.Settings
	oauth       *provider.OAuthProvider
}

func NewLoginHandler(appSettings *settings.Settings, oauth *provider.OAuthProvider) *loginHandler {
	return &loginHandler{
		appSettings: appSettings,
		oauth:       oauth,
	}
}

func (h *loginHandler) Handle(c context.Context) {
	domain := c.Query("d")
	dc, ok := h.appSettings.Domains[domain]
	if !ok {
		c.Error(http.StatusBadRequest, errors.New("invalid domain"))
		return
	}

	s := session.New(c, h.appSettings, dc)
	if s == nil {
		return
	}
	h.oauth.Login(c, s)
}
