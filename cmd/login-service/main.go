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
package main

import (
	"encoding/base64"
	"flag"
	"io/ioutil"
	syslogpkg "log/syslog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"

	"github.com/tink-ab/login-service/context"
	"github.com/tink-ab/login-service/handler"
	"github.com/tink-ab/login-service/provider"
	"github.com/tink-ab/login-service/provider/webauthn"
	"github.com/tink-ab/login-service/provider/webauthn/store"
	"github.com/tink-ab/login-service/session"
	"github.com/tink-ab/login-service/settings"
	"github.com/tink-ab/login-service/token"
)

var (
	config         = flag.String("config", "login-service.yaml", "Configuration file to load")
	validateConfig = flag.Bool("validate-config", false, "Validate config and exit")
	syslogStyle    = flag.String("syslog-format", "plain", "Output format of syslog [plain|json]")
	verbose        = flag.Bool("verbose", false, "Print debugging messages")
)

type Time struct{}

// Global login services
var syslog *log.Logger

// Token handlers
var tokenMinter *token.Minter
var tokenValidator *token.Validator

// Authentication providers
var oauth *provider.OAuthProvider
var webAuthn *webauthn.WebAuthnProvider
var webAuthnStore store.WebAuthnStore
var clock Time

func (t *Time) Now() time.Time {
	return time.Now()
}

func successHandler(c context.Context) {
	// Handler used if we are unable to figure out where to redirect the user
	// after authentication.
	c.HTML("success-no-redirect.tmpl", context.H{})
}

func mfaRedirect(s *session.LoginSession) string {
	return s.MFAURL
}

func finishedRedirect(s *session.LoginSession) string {
	return s.RedirectURL
}

func createToken(appSettings *settings.Settings, c context.Context, s *session.LoginSession) {
	log.Printf("%s: new token request from %s", s.Email, c.UserIP())
	s.PresenceValidated = true

	tokenTTL := appSettings.TokenTTL
	if duration, ok := appSettings.UserTokenTTLs[s.Email]; ok {
		log.Printf("%s: Assigning user-specific TTL of %s", s.Email, duration)
		tokenTTL = duration
	}

	cookie, err := tokenMinter.Create(s, tokenTTL)
	if err != nil {
		c.Error(http.StatusInternalServerError, err)
		return
	}

	expiryTime := clock.Now().Add(tokenTTL)

	v := base64.URLEncoding.EncodeToString(cookie)
	hc := http.Cookie{
		Name:     "Token-" + s.Domain,
		Path:     "/",
		Value:    v,
		Expires:  expiryTime,
		Secure:   true,
		HttpOnly: true,
		Domain:   appSettings.CookieDomain}
	c.SetCookie(&hc)
}

func mfaDisabledRedirect(appSettings *settings.Settings, c context.Context, s *session.LoginSession) {
	createToken(appSettings, c, s)
	c.Redirect(finishedRedirect(s))
}

func setup(appSettings *settings.Settings) {
	providers := make(map[string]token.Provider)
	providers["simple"] = token.NewSimpleProvider(appSettings.TokenGeneration, &clock)

	aes, err := base64.StdEncoding.DecodeString(appSettings.TokenAESKey)
	if err != nil {
		log.Fatalf("Unable to decode AES key: %s", err)
	}

	ec, err := base64.StdEncoding.DecodeString(appSettings.TokenECPrivateKey)
	if err != nil {
		log.Fatalf("Unable to decode EC private key: %s", err)
	}

	crypto := token.NewStdCrypto(aes)
	signer := token.NewEcdsaSigner(ec)
	verifier := token.NewEcdsaVerifier(signer.Public())
	tokenMinter = token.NewMinter(
		appSettings.MaxTokenTTL,
		crypto,
		signer,
		providers,
		appSettings.DefaultTokenProvider,
		&clock,
	)
	tokenValidator = token.NewValidator(crypto, verifier, providers, &clock)

	oauth = provider.NewOAuth(
		appSettings,
		mfaDisabledRedirect,
		mfaRedirect,
	)

	switch appSettings.WebAuthn.StoreType {
	case "filesystem":
		webAuthnStore = store.NewFilesystemStore(appSettings.WebAuthn.FilesystemStore.Path)
	case "s3":
		webAuthnStore = store.NewAWSS3Store(
			appSettings.WebAuthn.S3Store.Bucket,
			appSettings.WebAuthn.S3Store.Path,
			appSettings.WebAuthn.S3Store.CredentialRetryWait,
		)
	default:
		log.Fatalf("Unknown webstore store: %s", appSettings.WebAuthn.StoreType)
	}

	webAuthn = webauthn.NewProvider(appSettings,
		webAuthnStore,
		createToken,
		finishedRedirect,
	)
}

func errorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) == 0 {
			return
		}
		err := c.Errors[0].Err
		c.HTML(c.Writer.Status(), "error.tmpl", gin.H{
			"error":        err.Error(),
			"unauthorized": c.Writer.Status() == http.StatusUnauthorized,
			"forbidden":    c.Writer.Status() == http.StatusForbidden,
		})
	}
}

func newGin(appSettings *settings.Settings, withStatic bool) *gin.Engine {
	r := gin.New()
	r.Use(GinLogger(syslog, true))
	r.Use(GinLogger(log.StandardLogger(), false))
	r.Use(gin.Recovery())
	r.Use(errorHandler())

	if withStatic {
		r.Static("/css", filepath.Join(appSettings.StaticPath, "css"))
		r.Static("/img", filepath.Join(appSettings.StaticPath, "img"))
		r.Static("/js", filepath.Join(appSettings.StaticPath, "js"))
	}

	// Must load html templates, gin will crash if no HTML renderer
	// exists.
	r.LoadHTMLGlob(filepath.Join(appSettings.TemplatePath, "*.tmpl"))
	return r
}

func main() {
	flag.Parse()

	appSettings, err := settings.Parse(*config)
	if err != nil {
		log.Fatalf("Failed to read config: %s", err)
	}
	if *validateConfig {
		log.Println("Config loaded successfully")
		log.Exit(0)
	}

	syslog = log.New()
	syslog.Out = ioutil.Discard
	hook, err := logrus_syslog.NewSyslogHook("", "", syslogpkg.LOG_INFO, "")
	if err == nil {
		syslog.Hooks.Add(hook)
	}

	switch *syslogStyle {
	case "plain":
		syslog.Formatter = &log.TextFormatter{
			TimestampFormat: time.RFC3339,
			DisableColors:   true,
		}
	case "json":
		syslog.Formatter = &log.JSONFormatter{
			TimestampFormat: time.RFC3339,
		}
	}

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	setup(appSettings)

	login := newGin(appSettings, true)
	login.GET("/login/start", context.Wrap(handler.NewLoginHandler(appSettings, oauth).Handle))
	login.GET("/login/success", context.Wrap(successHandler))
	login.GET("/logout", context.Wrap(handler.NewLogoutHandler(appSettings).Handle))
	login.GET("/login/oauth2/callback", context.Wrap(session.Wrap(oauth.CallbackHandler)))
	login.GET("/login/webauthn", context.Wrap(session.Wrap(webAuthn.Handler)))
	login.GET("/login/webauthn/login/begin", context.Wrap(session.Wrap(webAuthn.BeginLoginHandler)))
	login.POST("/login/webauthn/login/finish", context.Wrap(session.Wrap(webAuthn.FinishLoginHandler)))
	login.GET("/login/webauthn/register/begin", context.Wrap(session.Wrap(webAuthn.BeginRegistrationHandler)))
	login.POST("/login/webauthn/register/finish", context.Wrap(session.Wrap(webAuthn.FinishRegistrationHandler)))

	go login.Run(appSettings.LoginAddress)

	list := newGin(appSettings, true)
	indexHandler := handler.NewIndexHandler(appSettings, webAuthnStore)
	list.GET("/", context.Wrap(indexHandler.Handle))
	list.GET("/list-users", context.Wrap(indexHandler.ListUsers))
	list.POST("/delete-user/:email", context.Wrap(indexHandler.DeleteUser))
	go list.Run(appSettings.UiAddress)

	auth := newGin(appSettings, false)
	auth.GET("/auth", context.Wrap(handler.NewAuthHandler(appSettings, tokenValidator).Handle))
	auth.Run(appSettings.AuthAddress)
}
