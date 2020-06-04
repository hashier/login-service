package user

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

type WebAuthnUser struct {
	Id          uint64
	Name        string
	Email       string
	Icon        string
	Credentials []webauthn.Credential
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

func NewWebAuthnUser(name string, email string, picture string) *WebAuthnUser {
	return &WebAuthnUser{
		Id:    randomUint64(),
		Name:  name,
		Email: email,
		Icon:  picture,
	}
}

func (user *WebAuthnUser) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(user.Id))
	return buf
}

func (user *WebAuthnUser) WebAuthnName() string {
	return user.Email
}

func (user *WebAuthnUser) WebAuthnDisplayName() string {
	return user.Name
}

func (user *WebAuthnUser) WebAuthnIcon() string {
	return user.Icon
}

func (user *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return user.Credentials
}

func (u *WebAuthnUser) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's Credentials
func (u *WebAuthnUser) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.Credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

func (u *WebAuthnUser) HasCredentials() bool {
	return len(u.WebAuthnCredentials()) > 0
}
