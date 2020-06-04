package settings

import (
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

const (
	defaultAuthAddress  = "[::1]:9090"
	defaultLoginAddress = "[::1]:9091"
	defaultUiAddress    = "[::1]:9092"
)

type DomainInfo struct {
	Description               string
	Groups                    []string
	Downstream                string
	GroupPassthroughFilter    string
	GroupPassthroughDelimiter string
	DisableMFA                bool `yaml:"disableMFA"'`
}

type OAuthSettings struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

type ServiceAccount struct {
	Email            string
	PrivateKey       string
	ImpersonateAdmin string
}

type Settings struct {
	AuthAddress  string `yaml:"authAddress"`
	LoginAddress string `yaml:"loginAddress"`
	UiAddress    string `yaml:"uiAddress"`

	StaticPath   string `yaml:"staticPath"`
	TemplatePath string `yaml:"templatePath"`

	// Path to load additional config from
	IncludeDomainsPath string `yaml:"includeDomainsPath"`

	// What scope is the token cookie valid for? (e.g. ".tink.se")
	CookieDomain string
	// How long should the tokens be valid for?
	TokenTTL time.Duration
	// How long should the tokens be valid for?
	MaxTokenTTL time.Duration
	// Which token provider to use for new tokens
	DefaultTokenProvider string
	// How long should a login session be allowed to last for?
	LoginSessionTTL time.Duration
	// What URL should the users be redirected to after OAuth?
	MFAURL string
	// What URL should the users be redirected to as a fallback?
	FallbackURL string
	// What domain must the redirect URL end with?
	AllowedRedirectDomain string
	// Token cookie AES key
	TokenAESKey string
	// Token cookie EC key
	TokenECPrivateKey string
	// Token generation for mass revoke
	TokenGeneration int

	// Client-driven OAuth configuration
	OAuth OAuthSettings

	// Server-to-server API credentials
	ServiceAccount ServiceAccount

	WebAuthn struct {
		DisplayName string `yaml:"displayName"`
		ID          string `yaml:"id"`
		Origin      string `yaml:"origin"`
		IconUrl     string `yaml:"iconUrl"`
		StoreType   string `yaml:"storeType"`
		S3Store     struct {
			Bucket              string        `yaml:"bucket"`
			Path                string        `yaml:"path"`
			CredentialRetryWait time.Duration `yaml:"credentialRetryWait"`
		} `yaml:"s3Store"`
		FilesystemStore struct {
			Path string `yaml:"path"`
		} `yaml:"filesystemStore"`
	} `yaml:"webAuthn"`

	DefaultGroupPassthroughDelimiter string
	Domains                          map[string]DomainInfo

	// User-specific TTLs
	UserTokenTTLs map[string]time.Duration

	AdminGroups []string `yaml:"adminGroups"`

	Contact struct {
		Url  string `yaml:"url"`
		Text string `yaml:"text"`
	} `yaml:"contact"`
}

func Parse(configFile string) (*Settings, error) {
	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to read config")
	}

	settings := &Settings{}
	err = yaml.Unmarshal(b, settings)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to decode config")
	}

	settings.MFAURL = "/login/webauthn?state=%s"
	settings.FallbackURL = "/login/success"

	if settings.AuthAddress == "" {
		settings.AuthAddress = defaultAuthAddress
	}
	if settings.LoginAddress == "" {
		settings.LoginAddress = defaultLoginAddress
	}
	if settings.UiAddress == "" {
		settings.UiAddress = defaultUiAddress
	}

	if p := settings.IncludeDomainsPath; p != "" {
		if err := settings.loadDomainsFromPath(p); err != nil {
			return nil, errors.Wrap(err, "Unable to load domains from path")
		}
	}

	return settings, nil
}

func StringIsInSlice(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

func (s Settings) IsInAdminGroup(groups []string) bool {
	for _, group := range groups {
		if StringIsInSlice(s.AdminGroups, group) {
			return true
		}
	}
	return false
}

func (s *Settings) loadDomainsFromPath(p string) error {
	fi, err := ioutil.ReadDir(p)
	if err != nil {
		return err
	}

	for _, f := range fi {
		fn := filepath.Join(p, f.Name())
		if filepath.Ext(fn) == ".yaml" {
			d, err := ioutil.ReadFile(fn)
			if err != nil {
				return err
			}
			ns := &Settings{}
			err = yaml.Unmarshal(d, ns)
			if err != nil {
				return errors.Errorf("%s %v", fn, err)
			}

			for k, v := range ns.Domains {
				if _, ok := s.Domains[k]; !ok {
					s.Domains[k] = v
				} else {
					return errors.Errorf("duplicate key %v in %v", k, fn)
				}
			}

		}
	}
	return nil
}
