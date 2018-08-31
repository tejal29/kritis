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

package isp

import (
	"reflect"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"github.com/grafeas/kritis/pkg/kritis/violation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestReview(t *testing.T) {
	sec := testutil.CreateSecret(t, "sec")
	vulnImage := testutil.QualifiedImage
	sigVuln, err := util.CreateAttestationSignature(vulnImage, sec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	noVulnImage := testutil.IntTestImage
	sigNoVuln, err := util.CreateAttestationSignature(noVulnImage, sec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	sMock := func(namespace string, name string) (*secrets.PGPSigningSecret, error) {
		return sec, nil
	}
	validAtts := []metadata.PGPAttestation{{Signature: sigVuln, KeyID: "sec"}}
	ispFetcher = func(ns string) ([]v1beta1.ImageSecurityPolicy, error) {
		return []v1beta1.ImageSecurityPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
				},
			},
		}, nil
	}
	authFetcher = func(ns string) ([]v1beta1.AttestationAuthority, error) {
		return []v1beta1.AttestationAuthority{{
			Spec: v1beta1.AttestationAuthoritySpec{
				NoteReference:        "provider/test",
				PrivateKeySecretName: "test",
				PublicKeyData:        sec.PublicKey,
			}}}, nil
	}
	testValidate := func(isp v1beta1.ImageSecurityPolicy, image string, client metadata.Fetcher) ([]securitypolicy.Violation, error) {
		if image == vulnImage {
			return []securitypolicy.Violation{
				{
					Vulnerability: metadata.Vulnerability{
						Severity: "foo",
					},
					Violation: 1,
				},
			}, nil
		}
		return nil, nil
	}
	tests := []struct {
		name              string
		image             string
		isWebhook         bool
		attestations      []metadata.PGPAttestation
		handledViolations int
		isAttested        bool
		shdAttestImage    bool
		shdErr            bool
	}{
		{
			name:              "vulnz w attestation for Webhook shd not handle voilations",
			image:             vulnImage,
			isWebhook:         true,
			attestations:      validAtts,
			handledViolations: 0,
			isAttested:        true,
			shdAttestImage:    false,
			shdErr:            false,
		},
		{
			name:              "vulnz w/o attestation for Webhook shd handle voilations",
			image:             vulnImage,
			isWebhook:         true,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 1,
			isAttested:        false,
			shdAttestImage:    false,
			shdErr:            true,
		},
		{
			name:              "no vulnz w/o attestation for webhook shd add attestation",
			image:             noVulnImage,
			isWebhook:         true,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 0,
			isAttested:        false,
			shdAttestImage:    true,
			shdErr:            false,
		},
		{
			name:              "vulnz w attestation for cron shd handle vuln",
			image:             vulnImage,
			isWebhook:         false,
			attestations:      validAtts,
			handledViolations: 1,
			isAttested:        true,
			shdAttestImage:    false,
			shdErr:            true,
		},
		{
			name:              "vulnz w/o attestation for cron shd handle vuln",
			image:             vulnImage,
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 1,
			isAttested:        false,
			shdAttestImage:    false,
			shdErr:            true,
		},
		{
			name:              "no vulnz w/o attestation for cron shd verify attestations",
			image:             noVulnImage,
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{},
			handledViolations: 0,
			isAttested:        false,
			shdAttestImage:    false,
			shdErr:            false,
		},
		{
			name:              "no vulnz w attestation for cron shd verify attestations",
			image:             noVulnImage,
			isWebhook:         false,
			attestations:      []metadata.PGPAttestation{{Signature: sigNoVuln, KeyID: "sec"}},
			handledViolations: 0,
			isAttested:        true,
			shdAttestImage:    false,
			shdErr:            false,
		},
	}
	for _, tc := range tests {
		th := violation.MemoryStrategy{
			Violations:   map[string]bool{},
			Attestations: map[string]bool{},
		}
		t.Run(tc.name, func(t *testing.T) {
			cMock := &testutil.MockMetadataClient{
				PGPAttestations: tc.attestations,
			}
			r := New(cMock, &Config{
				Validate:  testValidate,
				Secret:    sMock,
				IsWebhook: tc.isWebhook,
				Strategy:  &th,
			})
			if err := r.Review("test", []string{tc.image}, cMock, nil); (err != nil) != tc.shdErr {
				t.Errorf("expected review to return error %t, actual error %s", tc.shdErr, err)
			}
			if len(th.Violations) != tc.handledViolations {
				t.Errorf("expected to handle %d violations. Got %d", tc.handledViolations, len(th.Violations))
			}

			if th.Attestations[tc.image] != tc.isAttested {
				t.Errorf("expected to get image attested: %t. Got %t", tc.isAttested, th.Attestations[tc.image])
			}
			if (len(cMock.Occ) != 0) != tc.shdAttestImage {
				t.Errorf("expected an image to be attested, but found none")
			}
		})
	}
}

func TestGetUnAttested(t *testing.T) {
	tcs := []struct {
		name     string
		authIds  []string
		attIds   []string
		eAuthIds []string
	}{
		{"not equal", []string{"a", "b"}, []string{"a"}, []string{"b"}},
		{"equal", []string{"a", "b"}, []string{"a", "b"}, []string{}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			auths := makeAuth(tc.authIds)
			atts := makeAtt(tc.attIds)
			expected := makeAuth(tc.eAuthIds)
			actual := getUnAttested(auths, atts)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("Expected: %v\n Got: %v", expected, actual)
			}

		})
	}
}

func makeAuth(ids []string) []v1beta1.AttestationAuthority {
	l := make([]v1beta1.AttestationAuthority, len(ids))
	for i, s := range ids {
		l[i] = v1beta1.AttestationAuthority{
			Spec: v1beta1.AttestationAuthoritySpec{
				PrivateKeySecretName: s,
			},
		}
	}
	return l
}

func makeAtt(ids []string) []metadata.PGPAttestation {
	l := make([]metadata.PGPAttestation, len(ids))
	for i, s := range ids {
		l[i] = metadata.PGPAttestation{
			KeyID: s,
		}
	}
	return l
}
