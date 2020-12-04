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
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/tatianab/mint"
)

func TestMarshalUnmarshalJSONRegistrationRequest(t *testing.T) {
	oprfData := make([]byte, 32)
	_, _ = rand.Read(oprfData)

	regReq1 := &RegistrationRequest{
		UserID:   []byte("username"),
		OprfData: oprfData,
	}

	raw, err := regReq1.MarshalJSON()
	if err != nil {
		t.Error(err)
	}

	regReq2, err := UnmarshalRegistrationRequestJSON(raw)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(regReq1, regReq2) {
		t.Error("values not equal")
	}
}

func TestMarshalUnmarshalJSONRegistrationResponse(t *testing.T) {
	oprfData := make([]byte, 32)
	_, _ = rand.Read(oprfData)

	signer, err := mint.NewSigningKey(mint.ECDSA_P521_SHA512)
	if err != nil {
		t.Error(err)
	}

	regResp1 := &RegistrationResponse{
		OprfData:        oprfData,
		ServerPublicKey: signer.Public(),
		CredentialEncodingPolicy: &CredentialEncodingPolicy{
			SecretTypes:    []CredentialType{CredentialTypeUserPrivateKey},
			CleartextTypes: []CredentialType{CredentialTypeServerIdentity, CredentialTypeServerPublicKey},
		},
	}

	raw, err := regResp1.MarshalJSON()
	if err != nil {
		t.Error(err)
	}

	regResp2, err := UnmarshalRegistrationResponseJSON(raw)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(regResp1, regResp2) {
		t.Error("values not equal")
	}
}

func TestMarshalUnmarshalJSONRegistrationUpload(t *testing.T) {
	signer, err := mint.NewSigningKey(mint.ECDSA_P521_SHA512)
	if err != nil {
		t.Error(err)
		return
	}

	regUpload1 := &RegistrationUpload{
		Envelope:      getDummyEnvelope(),
		UserPublicKey: signer.Public(),
	}

	raw, err := regUpload1.MarshalJSON()
	if err != nil {
		t.Error(err)
	}

	regUpload2, err := UnmarshalRegistrationUploadJSON(raw)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(regUpload1, regUpload2) {
		t.Error("values not equal")
	}
}

func TestMarshalUnmarshalJSONCredentialRequest(t *testing.T) {
	oprfData := make([]byte, 32)
	_, _ = rand.Read(oprfData)

	credReq1 := &CredentialRequest{
		UserID:   []byte("username"),
		OprfData: oprfData,
	}

	raw, err := credReq1.MarshalJSON()
	if err != nil {
		t.Error(err)
	}

	credReq2, err := UnmarshalCredentialRequestJSON(raw)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(credReq1, credReq2) {
		t.Error("values not equal")
	}
}

func TestMarshalUnmarshalJSONCredentialResponse(t *testing.T) {
	oprfData := make([]byte, 32)
	_, _ = rand.Read(oprfData)

	signer, err := mint.NewSigningKey(mint.ECDSA_P256_SHA256)
	if err != nil {
		t.Error(err)
		return
	}

	cResp1 := &CredentialResponse{
		OprfData:        oprfData,
		Envelope:        getDummyEnvelope(),
		serverPublicKey: signer.Public(),
	}

	raw, err := cResp1.MarshalJSON()
	if err != nil {
		t.Error(err)
	}

	cResp2, err := UnmarshalCredentialResponseJSON(raw)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(cResp1, cResp2) {
		t.Error("values not equal")
	}
}
