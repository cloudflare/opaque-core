// Copyright (c) 2020, Cloudflare. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package opaque

import (
	"crypto"
	"crypto/x509"

	"github.com/tatianab/mint/syntax"
)

// A CredentialRequest is the first message sent by the client to initiate
// OPAQUE.
// Implements ProtocolMessageBody.
//
// struct {
// 	opaque id<0..2^16-1>;
// 	opaque data<1..2^16-1>;
// } CredentialRequest;
//
//        2                    2
// | userIDLen | userID | oprfDataLen | oprfData |
type CredentialRequest struct {
	UserID   []byte `tls:"head=2"`       // client account info, if present
	OprfData []byte `tls:"head=2,min=1"` // an encoded element in the OPRF group
}

var _ ProtocolMessageBody = (*CredentialRequest)(nil)

// Marshal returns the raw form of the struct.
func (cr *CredentialRequest) Marshal() ([]byte, error) {
	return syntax.Marshal(cr)
}

// Unmarshal puts raw data into fields of a struct.
func (cr *CredentialRequest) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, cr)
}

// Type returns the type of this struct.
func (*CredentialRequest) Type() ProtocolMessageType {
	return ProtocolMessageTypeCredentialRequest
}

// A CredentialResponse is the message sent by the server in response to
// the Client's initial OPAQUE message.
// Implements ProtocolMessageBody.
//
// struct {
// 	opaque data<1..2^16-1>;
// 	opaque envelope<1..2^16-1>;
// 	opaque pkS<0..2^16-1;
// } CredentialResponse;
//
//        2                                2
// | oprfDataLen | oprfData | envelope | pkSLen | pkS |
type CredentialResponse struct {
	OprfData        []byte           // an encoded element in the OPRF group
	Envelope        *Envelope        // an authenticated encoding of a Credentials structure
	serverPublicKey crypto.PublicKey // OPTIONAL: an encoded public key that will be used for the online authenticated key exchange stage.
}

// Type returns the type of this struct.
func (*CredentialResponse) Type() ProtocolMessageType {
	return ProtocolMessageTypeCredentialResponse
}

type credentialResponseInner struct {
	OprfData        []byte `tls:"head=2,min=1"`
	Envelope        *Envelope
	ServerPublicKey []byte `tls:"head=2"`
}

// Marshal encodes a Credential Response.
func (cr *CredentialResponse) Marshal() ([]byte, error) {
	rawPublicKey, err := x509.MarshalPKIXPublicKey(cr.serverPublicKey)
	if err != nil {
		return nil, err
	}

	toMarshal := &credentialResponseInner{
		cr.OprfData,
		cr.Envelope,
		rawPublicKey,
	}

	return syntax.Marshal(toMarshal)
}

// Unmarshal decodes a Credential Response.
func (cr *CredentialResponse) Unmarshal(data []byte) (int, error) {
	cri := new(credentialResponseInner)

	bytesRead, err := syntax.Unmarshal(data, cri)
	if err != nil {
		return 0, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(cri.ServerPublicKey)
	if err != nil {
		return 0, err
	}

	*cr = CredentialResponse{
		cri.OprfData, cri.Envelope, publicKey,
	}

	return bytesRead, nil
}
