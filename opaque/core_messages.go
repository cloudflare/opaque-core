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
	"github.com/cloudflare/opaque-core/common"
	"github.com/pkg/errors"
	"github.com/tatianab/mint/syntax"
)

// ProtocolMessageType indicates the OPAQUE protocol message type
//
// enum {
// 	registration_request(1),
// 	registration_response(2),
// 	registration_upload(3),
// 	credential_request(4),
// 	credential_response(5),
// 	(255)
// } ProtocolMessageType;.
type ProtocolMessageType byte

// OPAQUE protocol message types.
const (
	ProtocolMessageTypeRegistrationRequest ProtocolMessageType = 1 + iota
	ProtocolMessageTypeRegistrationResponse
	ProtocolMessageTypeRegistrationUpload
	ProtocolMessageTypeCredentialRequest
	ProtocolMessageTypeCredentialResponse
)

// A ProtocolMessage is a bundle containing all OPAQUE data sent in a flow
// between parties (during registration or login).
//
// struct {
// 	ProtocolMessageType msg_type;    /* protocol message type */
// 	uint24 length;                   /* remaining bytes in message */
// 	select (ProtocolMessage.msg_type) {
// 		case registration_request: RegistrationRequest;
// 		case registration_response: RegistrationResponse;
// 		case registration_upload: RegistrationUpload;
// 		case credential_request: CredentialRequest;
// 		case credential_response: CredentialResponse;
// 	};
// } ProtocolMessage;
//
//        1               3
// | messageType | messageBodyLen | messageBody |
type ProtocolMessage struct {
	MessageType    ProtocolMessageType
	MessageBodyRaw []byte `tls:"head=3"`
}

// Marshal encodes a ProtocolMessage.
func (msg *ProtocolMessage) Marshal() ([]byte, error) {
	return syntax.Marshal(msg)
}

// Unmarshal decodes a ProtocolMessage.
func (msg *ProtocolMessage) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, msg)
}

// ToBody assigns the message type.
func (msg *ProtocolMessage) ToBody() (ProtocolMessageBody, error) {
	var body ProtocolMessageBody

	switch msg.MessageType {
	case ProtocolMessageTypeRegistrationRequest:
		body = new(RegistrationRequest)
	case ProtocolMessageTypeRegistrationResponse:
		body = new(RegistrationResponse)
	case ProtocolMessageTypeRegistrationUpload:
		body = new(RegistrationUpload)
	case ProtocolMessageTypeCredentialRequest:
		body = new(CredentialRequest)
	case ProtocolMessageTypeCredentialResponse:
		body = new(CredentialResponse)
	default:
		return body, errors.Wrapf(common.ErrorUnrecognizedMessage, "message type %s", msg.MessageType)
	}

	return body, nil
}

// ProtocolMessageFromBody reconstructs a ProtocolMessage from its body.
func ProtocolMessageFromBody(body ProtocolMessageBody) (*ProtocolMessage, error) {
	bodyRaw, err := body.Marshal()
	if err != nil {
		return nil, err
	}

	return &ProtocolMessage{
		MessageType:    body.Type(),
		MessageBodyRaw: bodyRaw,
	}, nil
}

// ProtocolMessageBody is an interface implemented by all protocol messages.
// Represents the "inner" part of the message, not including metadata.
type ProtocolMessageBody interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) (int, error)
	Type() ProtocolMessageType
}
