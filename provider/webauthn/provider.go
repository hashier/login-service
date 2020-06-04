//
// Copyright 2019 Tink AB
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
package webauthn

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	log "github.com/sirupsen/logrus"

	"github.com/tink-ab/login-service/context"
	"github.com/tink-ab/login-service/provider"
	"github.com/tink-ab/login-service/provider/webauthn/store"
	webAuthnUser "github.com/tink-ab/login-service/provider/webauthn/user"
	"github.com/tink-ab/login-service/session"
	"github.com/tink-ab/login-service/settings"
)

type WebAuthnProvider struct {
	appSettings *settings.Settings

	webAuthn *webauthn.WebAuthn
	// Storage for WebAuthn users
	store store.WebAuthnStore
	// In-memory map of in-progress U2F sessionData
	sessionData map[string]*webauthn.SessionData

	// Our identification to the browser
	appID string

	// Function to call when a session has been authenticated by this module
	successCallback provider.SuccesCallback

	// Function to find out where to send the user when U2F is done
	nextURLCallback provider.NextURLCallback
}

func (p *WebAuthnProvider) BeginRegistrationHandler(c context.Context, s *session.LoginSession) {
	user, err := p.store.GetUser(s.Email)
	if err != nil {
		log.Errorf("failed to retrieve user: %v", err)
		c.Error(http.StatusInternalServerError, err)
		return
	}

	if user == nil {
		user = webAuthnUser.NewWebAuthnUser(s.Name, s.Email, s.Picture)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	options, sessionData, err := p.webAuthn.BeginRegistration(user, registerOptions)
	if err != nil {
		log.Errorf("webauthn: failed to begin registration: %v", err)
		c.Error(http.StatusInternalServerError, err)
		return
	}

	err = p.store.PutUser(user)
	if err != nil {
		log.Errorf("failed to store user: %v", err)
		c.Error(http.StatusInternalServerError, err)
		return
	}

	p.sessionData[s.SessionID] = sessionData

	c.JSON(options)
}

func (p *WebAuthnProvider) FinishRegistrationHandler(c context.Context, s *session.LoginSession) {
	user, err := p.store.GetUser(s.Email)
	if err != nil {
		log.Errorf("failed to retrieve user: %v", err)
		c.Error(http.StatusInternalServerError, err)
		return
	}
	if user == nil {
		err = fmt.Errorf("user not found: %s", s.Email)
		log.Error(err)
		c.Error(http.StatusInternalServerError, err)
		return
	}

	sessionData := p.sessionData[s.SessionID]

	credential, err := p.webAuthn.FinishRegistration(user, *sessionData, c.Request())
	if err != nil {
		log.Errorf("webauthn: failed to finish registration: %v", err)
		c.Error(http.StatusInternalServerError, err)
		return
	}

	user.AddCredential(*credential)
	err = p.store.PutUser(user)
	if err != nil {
		log.Errorf("failed to store user: %v", err)
		c.Error(http.StatusInternalServerError, err)
		return
	}

	c.String("success")
}

func (p *WebAuthnProvider) BeginLoginHandler(c context.Context, s *session.LoginSession) {
	user, err := p.store.GetUser(s.Email)
	if err != nil {
		log.Errorf("failed to retrieve user: %v", err)
		c.Error(http.StatusInternalServerError, err)
		return
	}
	if user == nil || !user.HasCredentials() {
		err = fmt.Errorf("user not found: %s", s.Email)
		log.Error(err)
		c.Error(http.StatusBadRequest, err)
		return
	}

	options, sessionData, err := p.webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		c.Error(http.StatusInternalServerError, err)
		return
	}

	p.sessionData[s.SessionID] = sessionData
	c.JSON(options)
}

func (p *WebAuthnProvider) FinishLoginHandler(c context.Context, s *session.LoginSession) {
	user, err := p.store.GetUser(s.Email)
	if err != nil {
		log.Errorf("failed to retrieve user: %v", err)
		c.Error(http.StatusInternalServerError, err)
		return
	}
	if user == nil || !user.HasCredentials() {
		err = fmt.Errorf("user not found: %s", s.Email)
		log.Error(err)
		c.Error(http.StatusBadRequest, err)
		return
	}

	sessionData := p.sessionData[s.SessionID]
	credential, err := p.webAuthn.FinishLogin(user, *sessionData, c.Request())

	if err != nil {
		log.Errorf("webauthn: failed to finish registration: %v", err)
		c.Error(http.StatusUnauthorized, err)
		return
	}

	if credential.Authenticator.CloneWarning {
		log.Errorf("webauthn: credential counter mismatch")
		c.Error(http.StatusUnauthorized, err)
		return
	}

	// store user with updated increments
	err = p.store.PutUser(user)
	if err != nil {
		log.Errorf("webauthn: failed to store incremented Credentials: %v", err)
		c.Error(http.StatusInternalServerError, err)
	}

	if p.successCallback != nil {
		p.successCallback(p.appSettings, c, s)
	}
	c.String("success")
}

func (p *WebAuthnProvider) Handler(c context.Context, s *session.LoginSession) {
	if s.Used {
		// Authentication succeeded
		c.Redirect(p.nextURLCallback(s))
		return
	}

	template := "webauthn-sign.tmpl"
	user, err := p.store.GetUser(s.Email)
	if err != nil {
		log.Errorf("Error reading U2F registration for %s: %s", s.Email, err)
		c.Error(http.StatusInternalServerError, errors.New("internal registration data invalid"))
		return
	}

	if user == nil || !user.HasCredentials() {
		template = "webauthn-registration.tmpl"
	}

	c.HTML(template, context.H{
		"name":        s.Name,
		"email":       s.Email,
		"picture":     s.Picture,
		"domain":      s.Domain,
		"state":       s.SessionID,
		"contactUrl":  p.appSettings.Contact.Url,
		"contactText": p.appSettings.Contact.Text,
	})
}

func (p *WebAuthnProvider) getUser(c context.Context, s *session.LoginSession) (*webAuthnUser.WebAuthnUser, error) {
	user, err := p.store.GetUser(s.Email)
	if err != nil {
		log.Errorf("failed to retrieve user: %v", err)
		return nil, err
	}
	if user == nil {
		err = fmt.Errorf("user not found: %s", s.Email)
		log.Error(err)
		return nil, err
	}

	return user, nil
}

func NewProvider(appSettings *settings.Settings, store store.WebAuthnStore, successCallback provider.SuccesCallback, nextURLCallback provider.NextURLCallback) *WebAuthnProvider {
	p := WebAuthnProvider{}
	p.appSettings = appSettings
	p.sessionData = make(map[string]*webauthn.SessionData)
	p.store = store
	p.successCallback = successCallback
	p.nextURLCallback = nextURLCallback

	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: appSettings.WebAuthn.DisplayName,
		RPID:          appSettings.WebAuthn.ID,
		RPOrigin:      appSettings.WebAuthn.Origin,
		RPIcon:        appSettings.WebAuthn.IconUrl,
	})
	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}
	p.webAuthn = webAuthn

	return &p
}
