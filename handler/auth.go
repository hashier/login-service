package handler

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/tink-ab/login-service/context"
	"github.com/tink-ab/login-service/settings"
	"github.com/tink-ab/login-service/token"
)

type authHandler struct {
	appSettings    *settings.Settings
	tokenValidator *token.Validator
}

func NewAuthHandler(appSettings *settings.Settings, tokenValidator *token.Validator) *authHandler {
	return &authHandler{
		appSettings:    appSettings,
		tokenValidator: tokenValidator,
	}
}

func (h *authHandler) Handle(c context.Context) {
	// The /auth enpoint accepts cookies through the Authorization HTTP header.
	// As it's in a cookies-type format we will need to re-process it so we can
	// access them in a sensible way.
	cookies := c.Authorization()
	r := fmt.Sprintf("GET / HTTP/1.0\r\nCookie: %s\r\n\r\n", cookies)
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(r)))
	if err != nil {
		c.Error(http.StatusUnauthorized, errors.New("invalid authorization"))
		return
	}

	domain := c.Query("d")
	dc, ok := h.appSettings.Domains[domain]
	if !ok {
		// intentional ambiguous error message
		c.Error(http.StatusUnauthorized, errors.New("invalid domain"))
		return
	}

	cookie, err := req.Cookie("Token-" + domain)
	if err != nil {
		c.Error(http.StatusUnauthorized, errors.New("missing token"))
		return
	}

	// Filter away the authentication cookies and leave the ones that we don't
	// manage. This is so the backend will be able to use cookies, but not
	// get access to the token cookies.
	fc := []string{}
	for _, co := range req.Cookies() {
		if strings.HasPrefix(co.Name, "Token-") {
			continue
		}
		fc = append(fc, co.String())
	}

	v, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		c.Error(http.StatusUnauthorized, errors.New("malformed token"))
		return
	}

	request, err := h.tokenValidator.Validate(v, domain, dc.Groups)
	if err == nil {
		downstreamGroups := filterDownstreamGroups(&dc, request)
		delim := h.appSettings.DefaultGroupPassthroughDelimiter
		if dc.GroupPassthroughDelimiter != "" {
			delim = dc.GroupPassthroughDelimiter
		}
		c.SetHeader("x-group", strings.Join(downstreamGroups, delim))
		c.SetHeader("x-downstream", dc.Downstream)
		c.SetHeader("x-user", request.User)
		c.SetHeader("x-domain", domain)
		// Pass along the rest of the cookies to pass downstream
		c.SetHeader("x-cookie", strings.Join(fc, ";"))
		c.String("success")
		log.Printf("User %s accessing %s from %s", request.User, domain, c.UserIP())
	} else {
		c.Error(http.StatusUnauthorized, err)
	}
}

func filterDownstreamGroups(currDomain *settings.DomainInfo, request *token.Request) []string {
	// pass through groups to downstream if they match the configured
	// PassthroughFilter for the domain.
	// Return the current domain's groups if the user is in them

	// anchor the regex
	var re *regexp.Regexp
	if currDomain.GroupPassthroughFilter != "" {
		var err error
		re, err = regexp.Compile("^" + currDomain.GroupPassthroughFilter + "$")
		if err != nil {
			log.Errorf("The configured regexp is invalid: %s", currDomain.GroupPassthroughFilter)
			re = nil
		}
	}

	var groups []string
	for _, group := range request.Groups {
		if settings.StringIsInSlice(currDomain.Groups, group) || (re != nil && re.MatchString(group)) {
			groups = append(groups, group)
		}
	}

	return groups
}
