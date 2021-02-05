package opaque

import (
	"crypto/x509"
	"encoding/json"
)

func (pmt ProtocolMessageType) String() string {
	return ProtocolMessageTypeToStringMap[pmt]
}

// ProtocolMessageTypeToStringMap maps the Protocol Message Type to its string equivalent.
var ProtocolMessageTypeToStringMap = map[ProtocolMessageType]string{
	ProtocolMessageTypeRegistrationRequest:  "OPAQUE Registration Request",
	ProtocolMessageTypeRegistrationResponse: "OPAQUE Registration Response",
	ProtocolMessageTypeRegistrationUpload:   "OPAQUE Registration Upload",
	ProtocolMessageTypeCredentialRequest:    "OPAQUE Credential Request",
	ProtocolMessageTypeCredentialResponse:   "OPAQUE Credential Response",
}

type registrationRequestJSON struct {
	UserID   []byte
	OprfData []byte
}

// MarshalJSON encodes the RegistrationRequest.
func (rr *RegistrationRequest) MarshalJSON() ([]byte, error) {
	rrJSON := &registrationRequestJSON{
		UserID:   rr.UserID,
		OprfData: rr.OprfData,
	}

	return json.Marshal(rrJSON)
}

// UnmarshalRegistrationRequestJSON decodes to a RegistrationRequest.
func UnmarshalRegistrationRequestJSON(b []byte) (*RegistrationRequest, error) {
	h := &RegistrationRequest{}
	err := json.Unmarshal(b, h)
	if err != nil {
		return nil, err
	}

	return h, nil
}

type registrationResponseJSON struct {
	OprfData        []byte
	ServerPublicKey []byte
	SecretTypes     []byte
	CleartextTypes  []byte
}

// MarshalJSON encodes the RegistrationResponse.
func (rr *RegistrationResponse) MarshalJSON() ([]byte, error) {
	rawPubKey, err := x509.MarshalPKIXPublicKey(rr.ServerPublicKey)
	if err != nil {
		return nil, err
	}

	var secTypes []byte
	for _, s := range rr.CredentialEncodingPolicy.SecretTypes {
		secTypes = append(secTypes, byte(s))
	}

	var clearTypes []byte
	for _, cl := range rr.CredentialEncodingPolicy.CleartextTypes {
		clearTypes = append(clearTypes, byte(cl))
	}
	rrJSON := &registrationResponseJSON{
		OprfData:        rr.OprfData,
		ServerPublicKey: rawPubKey,
		SecretTypes:     secTypes,
		CleartextTypes:  clearTypes,
	}

	return json.Marshal(rrJSON)
}

// UnmarshalRegistrationResponseJSON decodes to a RegistrationResponse.
func UnmarshalRegistrationResponseJSON(b []byte) (*RegistrationResponse, error) {
	rrJSON := &registrationResponseJSON{}
	err := json.Unmarshal(b, rrJSON)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(rrJSON.ServerPublicKey)
	if err != nil {
		return nil, err
	}

	var secTypes []CredentialType
	for _, s := range rrJSON.SecretTypes {
		secTypes = append(secTypes, CredentialType(s))
	}

	var clearTypes []CredentialType
	for _, cl := range rrJSON.CleartextTypes {
		clearTypes = append(clearTypes, CredentialType(cl))
	}

	cred := &CredentialEncodingPolicy{
		SecretTypes:    secTypes,
		CleartextTypes: clearTypes,
	}

	r := &RegistrationResponse{
		OprfData:                 rrJSON.OprfData,
		ServerPublicKey:          pubKey,
		CredentialEncodingPolicy: cred,
	}

	return r, nil
}

type registrationUploadJSON struct {
	UserPublicKey      []byte
	Nonce              []byte
	EncryptedCreds     []byte
	AuthenticatedCreds []byte
	AuthTag            []byte
}

// MarshalJSON encodes the RegistrationUpload.
func (rr *RegistrationUpload) MarshalJSON() ([]byte, error) {
	rawPubKey, err := x509.MarshalPKIXPublicKey(rr.ClientPublicKey)
	if err != nil {
		return nil, err
	}

	rrJSON := &registrationUploadJSON{
		UserPublicKey:      rawPubKey,
		Nonce:              rr.Envelope.Nonce,
		EncryptedCreds:     rr.Envelope.EncryptedCreds,
		AuthenticatedCreds: rr.Envelope.AuthenticatedCreds,
		AuthTag:            rr.Envelope.AuthTag,
	}

	return json.Marshal(rrJSON)
}

// UnmarshalRegistrationUploadJSON decodes to a RegistrationRequest.
func UnmarshalRegistrationUploadJSON(b []byte) (*RegistrationUpload, error) {
	rrJSON := &registrationUploadJSON{}
	err := json.Unmarshal(b, rrJSON)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(rrJSON.UserPublicKey)
	if err != nil {
		return nil, err
	}

	env := &Envelope{
		Nonce:              rrJSON.Nonce,
		EncryptedCreds:     rrJSON.EncryptedCreds,
		AuthenticatedCreds: rrJSON.AuthenticatedCreds,
		AuthTag:            rrJSON.AuthTag,
	}
	r := &RegistrationUpload{
		Envelope:        env,
		ClientPublicKey: pubKey,
	}

	return r, nil
}

type credentialRequestJSON struct {
	UserID   []byte
	OprfData []byte
}

// MarshalJSON encodes the CredentialRequest.
func (cr *CredentialRequest) MarshalJSON() ([]byte, error) {
	crJSON := &credentialRequestJSON{
		UserID:   cr.UserID,
		OprfData: cr.OprfData,
	}

	return json.Marshal(crJSON)
}

// UnmarshalCredentialRequestJSON decodes to a CredentialRequest.
func UnmarshalCredentialRequestJSON(b []byte) (*CredentialRequest, error) {
	c := &CredentialRequest{}
	err := json.Unmarshal(b, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

type credentialResponseJSON struct {
	OprfData           []byte
	Nonce              []byte
	EncryptedCreds     []byte
	AuthenticatedCreds []byte
	AuthTag            []byte
	ServerPublicKey    []byte
}

// MarshalJSON encodes the CredentialResponse.
func (cr *CredentialResponse) MarshalJSON() ([]byte, error) {
	rawPubKey, err := x509.MarshalPKIXPublicKey(cr.serverPublicKey)
	if err != nil {
		return nil, err
	}

	crJSON := &credentialResponseJSON{
		OprfData:           cr.OprfData,
		Nonce:              cr.Envelope.Nonce,
		EncryptedCreds:     cr.Envelope.EncryptedCreds,
		AuthenticatedCreds: cr.Envelope.AuthenticatedCreds,
		AuthTag:            cr.Envelope.AuthTag,
		ServerPublicKey:    rawPubKey,
	}

	return json.Marshal(crJSON)
}

// UnmarshalCredentialResponseJSON decodes to a CredentialResponse.
func UnmarshalCredentialResponseJSON(b []byte) (*CredentialResponse, error) {
	crJSON := &credentialResponseJSON{}
	err := json.Unmarshal(b, crJSON)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(crJSON.ServerPublicKey)
	if err != nil {
		return nil, err
	}

	env := &Envelope{
		Nonce:              crJSON.Nonce,
		EncryptedCreds:     crJSON.EncryptedCreds,
		AuthenticatedCreds: crJSON.AuthenticatedCreds,
		AuthTag:            crJSON.AuthTag,
	}
	cr := &CredentialResponse{
		OprfData:        crJSON.OprfData,
		Envelope:        env,
		serverPublicKey: pubKey,
	}

	return cr, nil
}

// String returns the string equivalent of the Credential Type.
func (ct CredentialType) String() string {
	switch ct {
	case CredentialTypeUserPrivateKey:
		return "User Private Key"
	case CredentialTypeUserPublicKey:
		return "User Public Key"
	case CredentialTypeServerPublicKey:
		return "Server Public Key"
	case CredentialTypeUserIdentity:
		return "User Identity"
	case CredentialTypeServerIdentity:
		return "Server Identity"
	}

	return "Unrecognized Credential Type"
}

// MarshalText encodes the Credential Type.
func (ct CredentialType) MarshalText() ([]byte, error) {
	return []byte(ct.String()), nil
}
