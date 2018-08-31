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

package util

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

func TestHasAnyValidAttestations(t *testing.T) {
	successSec := testutil.CreateSecret(t, "test-success")
	sig, err := CreateAttestationSignature(testutil.QualifiedImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	anotherSig, err := CreateAttestationSignature(testutil.IntTestImage, successSec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	host, err := container.NewAtomicContainerSig(testutil.QualifiedImage, map[string]string{})
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
				KeyID:     "test-success",
			}, {
				Signature: "invalid-sig",
				KeyID:     "test-sucess",
			}}},
		{"no valid sig", false, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyID:     "test-sucess",
			}}},
		{"invalid secret", false, []metadata.PGPAttestation{
			{
				Signature: "invalid-sig",
				KeyID:     "invalid",
			}}},
		{"valid sig over another host", false, []metadata.PGPAttestation{
			{
				Signature: anotherSig,
				KeyID:     "test-success",
			}}},
	}
	secs := map[string]*secrets.PGPSigningSecret{
		"test-success": successSec,
	}
	sMock := func(namespace string, name string) (*secrets.PGPSigningSecret, error) {
		s, ok := secs[name]
		if !ok {
			return nil, fmt.Errorf("secret not found")
		}
		return s, nil
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual := HasAnyValidHostSignature(host, tc.attestations, "test-namespace", sMock)
			if actual != tc.expected {
				t.Fatalf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}
}

func TestHasAllValidAttestations(t *testing.T) {
	successSec1 := testutil.CreateSecret(t, "test-success-1")
	sig1, err := CreateAttestationSignature(testutil.QualifiedImage, successSec1)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	successSec2 := testutil.CreateSecret(t, "test-success-2")
	sig2, err := CreateAttestationSignature(testutil.QualifiedImage, successSec2)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	host, err := container.NewAtomicContainerSig(testutil.QualifiedImage, map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	tcs := []struct {
		name         string
		expected     bool
		attestations []metadata.PGPAttestation
		required     map[string]bool
	}{
		{"all sig valid", true, []metadata.PGPAttestation{
			{
				Signature: sig1,
				KeyID:     "test-success-1",
			}, {
				Signature: sig2,
				KeyID:     "test-success-2",
			}},
			map[string]bool{
				"test-success-1": true,
				"test-success-2": true,
			}},
		{"invalid req sig", false, []metadata.PGPAttestation{
			{
				Signature: sig1,
				KeyID:     "test-success-1",
			}, {
				Signature: "invalid-sig2",
				KeyID:     "test-success-2",
			}},
			map[string]bool{
				"test-success-1": true,
				"test-success-2": true,
			}},
		{"invalid not req sig should return success", true, []metadata.PGPAttestation{
			{
				Signature: sig1,
				KeyID:     "test-success-1",
			}, {
				Signature: "invalid-sig2",
				KeyID:     "test-success-2",
			}},
			map[string]bool{
				"test-success-1": true,
			}},
	}
	secs := map[string]*secrets.PGPSigningSecret{
		"test-success-1": successSec1,
		"test-success-2": successSec2,
	}
	sMock := func(namespace string, name string) (*secrets.PGPSigningSecret, error) {
		s, ok := secs[name]
		if !ok {
			return nil, fmt.Errorf("secret not found")
		}
		return s, nil
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual := HasAllValidHostSignature(host, tc.attestations, "test-namespace", tc.required, sMock)
			if actual != tc.expected {
				t.Fatalf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}
}

func TestUniqueImages(t *testing.T) {
	tcs := []struct {
		name     string
		input    []string
		expected []string
	}{
		{"dupliactes", []string{"a", "b", "a"}, []string{"a", "b"}},
		{"uniq", []string{"a", "b"}, []string{"a", "b"}},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			actual := UniqueImages(tc.input)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Fatalf("Expected %v, Got %v", tc.expected, actual)
			}
		})
	}
}
