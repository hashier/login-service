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
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"path"

	"github.com/tink-ab/login-service/provider/webauthn/user"
)

type WebAuthnStore interface {
	GetUser(email string) (*user.WebAuthnUser, error)
	PutUser(user *user.WebAuthnUser) error
	DeleteUser(email string) error
	ListUsers() ([]user.WebAuthnUser, error)
}

func filename(dir string, email string, suffix string) string {
	hash := sha256.Sum256([]byte(email))
	return path.Join(dir, hex.EncodeToString(hash[:])+suffix)
}
