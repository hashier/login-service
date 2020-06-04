package handler

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/tink-ab/login-service/context"
	"github.com/tink-ab/login-service/provider/webauthn/store"
	"github.com/tink-ab/login-service/settings"
)

type indexHandler struct {
	appSettings *settings.Settings
	store       store.WebAuthnStore
}

func NewIndexHandler(appSettings *settings.Settings, webAuthnStore store.WebAuthnStore) *indexHandler {
	return &indexHandler{
		appSettings: appSettings,
		store:       webAuthnStore,
	}
}

func (h *indexHandler) Handle(c context.Context) {
	// Groups are set in the /auth endpoint
	groups := h.userGroups(c)
	index := make(map[string]settings.DomainInfo)

	isAdmin := h.appSettings.IsInAdminGroup(groups)

	// loop through appSettings.domains and match against groups
	for url, domain := range h.appSettings.Domains {
		for _, group := range groups {
			if settings.StringIsInSlice(domain.Groups, group) {
				index[url] = domain
				break
			}
		}
	}

	c.HTML("index.tmpl", context.H{
		"index":   index,
		"isAdmin": isAdmin,
	})
}

func (h *indexHandler) ListUsers(c context.Context) {
	groups := h.userGroups(c)
	if !h.appSettings.IsInAdminGroup(groups) {
		c.Error(http.StatusForbidden, errors.New("forbidden"))
		return
	}

	webAuthnUsers, err := h.store.ListUsers()
	if err != nil {
		c.Error(http.StatusInternalServerError, err)
		return
	}

	sort.Slice(webAuthnUsers, func(i, j int) bool {
		return webAuthnUsers[i].Name < webAuthnUsers[j].Name
	})
	var users []map[string]string
	for _, webAuthnUser := range webAuthnUsers {
		users = append(users, map[string]string{
			"name":    webAuthnUser.Name,
			"email":   webAuthnUser.Email,
			"picture": webAuthnUser.Icon,
		})
	}

	c.HTML("list-users.tmpl", context.H{
		"users": users,
	})
}

func (h *indexHandler) DeleteUser(c context.Context) {
	groups := h.userGroups(c)
	if !h.appSettings.IsInAdminGroup(groups) {
		c.Error(http.StatusForbidden, errors.New("forbidden"))
		return
	}

	email := c.Param("email")
	if err := h.store.DeleteUser(email); err != nil {
		c.Error(http.StatusInternalServerError, err)
		return
	}

	c.String("success")
}

func (h *indexHandler) userGroups(c context.Context) []string {
	return strings.Split(c.Groups(), h.appSettings.DefaultGroupPassthroughDelimiter)
}
