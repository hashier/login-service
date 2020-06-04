//
// Copyright 2017 Tink AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package provider

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	admin "google.golang.org/api/admin/directory/v1"

	"github.com/tink-ab/login-service/context"
	"github.com/tink-ab/login-service/session"
	"github.com/tink-ab/login-service/settings"
)

// User is a retrieved and authentiacted user.
type User struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
}

type OAuthProvider struct {
	appSettings *settings.Settings

	// Client-driven OAuth configuration (for login)
	oauth *oauth2.Config

	// Server-to-server communication (group lookup)
	adminService *admin.Service

	// Function to call when a session has been authenticated by this module
	mfaDisabledCallback SuccesCallback

	// Function to find out where to send the user when U2F is done
	nextURLCallback NextURLCallback
}

func (p *OAuthProvider) getGroups(email string) ([]string, error) {
	g, err := p.adminService.Groups.List().UserKey(email).Do()
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, group := range g.Groups {
		if !group.AdminCreated {
			continue
		}
		groups = append(groups, group.Email)
	}
	log.Debugf("%s is member of %v", email, groups)
	return groups, nil
}

func (p *OAuthProvider) Login(c context.Context, s *session.LoginSession) {
	c.Redirect(p.oauth.AuthCodeURL(s.SessionID))
}

func (p *OAuthProvider) CallbackHandler(c context.Context, s *session.LoginSession) {
	tok, err := p.oauth.Exchange(oauth2.NoContext, c.Query("code"))
	if err != nil {
		log.Printf("oauth token invalid: %s", err)
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}

	client := p.oauth.Client(oauth2.NoContext, tok)
	email, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Errorf("oauth userinfo request failed: %s", err)
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}
	defer email.Body.Close()
	data, _ := ioutil.ReadAll(email.Body)

	var user User
	err = json.Unmarshal(data, &user)
	if err != nil {
		log.Errorf("Failed to deserialize json: %s", err)
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}
	log.Debugf("Got user data: %s", string(data))

	// Sanity check results
	if user.Email == "" {
		log.Errorf("Failed user sanity check")
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}

	// We now known things about the user
	s.Name = user.Name
	s.Email = user.Email
	s.Picture = user.Picture
	groups, err := p.getGroups(s.Email)
	if err != nil {
		log.Errorf("Failed to get groups: %s", err)
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}
	s.Groups = groups

	// Check if the user is a member of the required group
	found := false
	for _, group := range groups {
		if settings.StringIsInSlice(s.DomainInfo.Groups, group) {
			found = true
			break
		}
	}
	if !found {
		log.Printf("user is not member of required group %s", strings.Join(s.DomainInfo.Groups, ", "))
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}

	if s.DomainInfo.DisableMFA && p.mfaDisabledCallback != nil {
		p.mfaDisabledCallback(p.appSettings, c, s)
		return
	}

	c.Redirect(p.nextURLCallback(s))
}

func NewOAuth(appSettings *settings.Settings, mfaDisabledCallback SuccesCallback, nextURLCallback NextURLCallback) *OAuthProvider {
	p := OAuthProvider{}

	p.appSettings = appSettings

	// Admin client used for server-to-server communication
	scope := admin.AdminDirectoryGroupReadonlyScope
	cfg := &jwt.Config{
		Email:      appSettings.ServiceAccount.Email,
		PrivateKey: []byte(appSettings.ServiceAccount.PrivateKey),
		Scopes:     []string{scope},
		TokenURL:   google.JWTTokenURL,
	}
	cfg.Subject = appSettings.ServiceAccount.ImpersonateAdmin
	client := cfg.Client(oauth2.NoContext)
	service, err := admin.New(client)
	if err != nil {
		log.Fatalf("error constructing admin service: %s", err)
	}
	p.adminService = service

	// OAuth2 client used for client driven authentication (login)
	p.oauth = &oauth2.Config{
		ClientID:     appSettings.OAuth.ClientID,
		ClientSecret: appSettings.OAuth.ClientSecret,
		RedirectURL:  appSettings.OAuth.CallbackURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	p.mfaDisabledCallback = mfaDisabledCallback
	p.nextURLCallback = nextURLCallback

	return &p
}
