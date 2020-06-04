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
	"bytes"
	"context"
	"encoding/gob"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
	"github.com/tink-ab/login-service/provider/webauthn/user"
)

type AWSS3WebAuthnStore struct {
	bucketName string
	path       string
	s3Client   *s3.S3
}

func waitUntilValidSession(credentialRetryWait time.Duration) *session.Session {
	awsSession := session.Must(session.NewSession())

	for {
		_, err := awsSession.Config.Credentials.Get()
		if err != credentials.ErrNoValidProvidersFoundInChain {
			return awsSession
		}

		log.Errorf("Failed get retrieve AWS credentials. Retrying.. %v", err)
		awsSession = session.Must(session.NewSession())
		time.Sleep(credentialRetryWait)
	}
}

func (a *AWSS3WebAuthnStore) filename(email string) string {
	return filename(a.path, email, ".gob")
}

func (a *AWSS3WebAuthnStore) read(fileName string) (*user.WebAuthnUser, error) {
	getObjectInput := s3.GetObjectInput{
		Bucket: &a.bucketName,
		Key:    &fileName,
	}
	getObjectOutput, err := a.s3Client.GetObjectWithContext(context.Background(), &getObjectInput)
	if err != nil {
		if requestErr, ok := err.(awserr.RequestFailure); ok {
			if requestErr.StatusCode() == 404 {
				return nil, nil
			}
		}

		return nil, err
	}

	dec := gob.NewDecoder(getObjectOutput.Body)
	var webAuthnUser user.WebAuthnUser
	err = dec.Decode(&webAuthnUser)
	if err != nil {
		return nil, err
	}

	return &webAuthnUser, nil
}

func (a *AWSS3WebAuthnStore) write(email string, webAuthnUser *user.WebAuthnUser) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(webAuthnUser); err != nil {
		return err
	}
	body := bytes.NewReader(buf.Bytes())

	fileName := a.filename(email)
	putObjectInput := s3.PutObjectInput{
		Bucket: &a.bucketName,
		Key:    &fileName,
		Body:   body,
	}
	_, err := a.s3Client.PutObjectWithContext(context.Background(), &putObjectInput)
	return err
}

func (a *AWSS3WebAuthnStore) GetUser(email string) (*user.WebAuthnUser, error) {
	webAuthnUser, err := a.read(a.filename(email))
	if err != nil {
		return nil, err
	}

	return webAuthnUser, nil
}

func (a *AWSS3WebAuthnStore) PutUser(user *user.WebAuthnUser) error {
	return a.write(user.Email, user)
}

func (a *AWSS3WebAuthnStore) DeleteUser(email string) error {
	fileName := a.filename(email)
	deleteObjectInput := s3.DeleteObjectInput{
		Bucket: &a.bucketName,
		Key:    &fileName,
	}
	_, err := a.s3Client.DeleteObjectWithContext(context.Background(), &deleteObjectInput)
	return err
}

func (a *AWSS3WebAuthnStore) ListUsers() ([]user.WebAuthnUser, error) {
	listObjectsInput := s3.ListObjectsV2Input{
		Bucket: &a.bucketName,
	}

	var users []user.WebAuthnUser
	err := a.s3Client.ListObjectsV2PagesWithContext(
		context.Background(),
		&listObjectsInput,
		func(output *s3.ListObjectsV2Output, lastPage bool) bool {
			for _, content := range output.Contents {
				webAuthnUser, err := a.read(*content.Key)
				if err != nil {
					log.Errorf("failed to fetch user %v", err)
					continue
				}
				users = append(users, *webAuthnUser)
			}
			return !lastPage
		})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func NewAWSS3Store(bucket string, path string, credentialRetryWait time.Duration) *AWSS3WebAuthnStore {
	awsSession := waitUntilValidSession(credentialRetryWait)
	s3Client := s3.New(awsSession)
	return &AWSS3WebAuthnStore{
		bucketName: bucket,
		path:       path,
		s3Client:   s3Client,
	}
}
