/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package review

import (
	"fmt"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"github.com/grafeas/kritis/pkg/kritis/util"
)

func TestHasValidAttestations(t *testing.T) {
	successSec := testutil.CreateSecret(t, "test-success")
	sig, err := util.CreateAttestationSignature(testutil.QualifiedImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	anotherSig, err := util.CreateAttestationSignature(testutil.IntTestImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	tcs := []struct {
		name         string
		expected     bool
		attestations []metadata.PGPAttestation
	}{
		{"atleast one valid sig", true, []metadata.PGPAttestation{
			{
				Signature: sig,
				KeyId:     "test-success",
			}, {
				Signature: "invalid-sig",
				KeyId:     "test-sucess",
			}}},
		{"no valid sig", false, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyId:     "test-sucess",
			}}},
		{"invalid secret", false, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyId:     "invalid",
			}}},
		{"valid sig over another host", false, []metadata.PGPAttestation{
			{
				Signature: anotherSig,
				KeyId:     "test-success",
			}}},
	}
	secs := map[string]*secrets.PGPSigningSecret{
		"test-success": successSec,
	}
	mSecretFetcher := func(namespace string, name string) (*secrets.PGPSigningSecret, error) {
		s, ok := secs[name]
		if !ok {
			return nil, fmt.Errorf("secret not found")
		}
		return s, nil
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			client := testutil.MockMetadataClient{
				PGPAttestations: tc.attestations,
			}
			actual := hasValidImageAttestations(testutil.QualifiedImage, client, "test-namespace", mSecretFetcher)
			if actual != tc.expected {
				t.Fatalf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}
}
