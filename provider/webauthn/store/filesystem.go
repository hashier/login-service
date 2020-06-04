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
	"encoding/gob"
	"os"
	"path/filepath"

	"github.com/tink-ab/login-service/provider/webauthn/user"
)

type FilesystemWebAuthnStore struct {
	path string
}

func (s *FilesystemWebAuthnStore) filename(email string) string {
	return filename(s.path, email, ".gob")
}

func (s *FilesystemWebAuthnStore) read(filename string) (*user.WebAuthnUser, error) {
	f, err := os.Open(filename)
	if err != nil {
		// If the file is not there, it's not an error but just no data available.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	dec := gob.NewDecoder(f)
	var webAuthnUser user.WebAuthnUser
	err = dec.Decode(&webAuthnUser)
	if err != nil {
		return nil, err
	}
	return &webAuthnUser, nil
}

func (s *FilesystemWebAuthnStore) write(email string, webAuthnUser *user.WebAuthnUser) error {
	f, err := os.OpenFile(s.filename(email), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer func() {
		f.Sync()
		f.Close()
	}()

	enc := gob.NewEncoder(f)
	return enc.Encode(webAuthnUser)
}

func (s *FilesystemWebAuthnStore) GetUser(email string) (*user.WebAuthnUser, error) {
	f, err := s.read(s.filename(email))
	if err != nil {
		return nil, err
	}

	return f, nil
}

func (s *FilesystemWebAuthnStore) PutUser(user *user.WebAuthnUser) error {
	return s.write(user.Email, user)
}

func (s *FilesystemWebAuthnStore) DeleteUser(email string) error {
	return os.Remove(s.filename(email))
}

func (s *FilesystemWebAuthnStore) ListUsers() ([]user.WebAuthnUser, error) {
	var users []user.WebAuthnUser
	err := filepath.Walk(s.path, func(file string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		webAuthUser, err := s.read(file)
		if err != nil {
			return err
		}
		users = append(users, *webAuthUser)
		return nil
	})
	return users, err
}

func NewFilesystemStore(path string) *FilesystemWebAuthnStore {
	s := FilesystemWebAuthnStore{}
	s.path = path
	return &s
}
