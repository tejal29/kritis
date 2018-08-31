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
	"os"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/spf13/cobra"
	cpb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
)

func ExitIfErr(cmd *cobra.Command, err error) {
	if err != nil {
		cmd.Println(err)
		os.Exit(1)
	}
}

// UniqueImages returns unique images in the list of images.
func UniqueImages(images []string) []string {
	m := map[string]bool{}
	l := []string{}
	for _, i := range images {
		if _, ok := m[i]; !ok {
			m[i] = true
			l = append(l, i)
		}
	}
	return l
}

func CreateAttestationSignature(image string, pgpSigningKey *secrets.PGPSigningSecret) (string, error) {
	hostSig, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		return "", err
	}
	hostStr, err := hostSig.JSON()
	if err != nil {
		return "", err
	}
	return attestation.CreateMessageAttestation(pgpSigningKey.PublicKey, pgpSigningKey.PrivateKey, hostStr)
}

// GetOrCreateAttestationNote returns a note if exists and creates one if it does not exist.
func GetOrCreateAttestationNote(c metadata.Fetcher, a *v1beta1.AttestationAuthority) (*cpb.Note, error) {
	n, err := c.AttestationNote(a)
	if err == nil {
		return n, nil
	}
	return c.CreateAttestationNote(a)
}

// HasAllValidHostSignature returns true if valid attestations are present for AttestationAuthorities in auths.
// If auths is a map of AttestationAuthority Name.
func HasAllValidHostSignature(h *container.AtomicContainerSig, p []metadata.PGPAttestation, ns string, auths map[string]bool, secret secrets.Fetcher) bool {
	for _, a := range p {
		if _, ok := auths[a.KeyID]; !ok {
			continue
		}
		// Get Secret from key id.
		s, err := secret(ns, a.KeyID)
		if err != nil {
			glog.Errorf("could not find secret %s in namespace %s for attestation verification", a.KeyID, ns)
			return false
		}
		if err = h.VerifyAttestationSignature(s.PublicKey, a.Signature); err != nil {
			glog.Errorf("could not find verify attestation for attestation authority %s", a.KeyID)
			return false
		}
	}
	return true
}

// HasAnyValidHostSignature returns true if one valid attestation exists.
func HasAnyValidHostSignature(h *container.AtomicContainerSig, p []metadata.PGPAttestation,
	ns string, secret secrets.Fetcher) bool {

	for _, a := range p {
		// Get Secret from key id.
		s, err := secret(ns, a.KeyID)
		if err != nil {
			glog.Errorf("could not find secret %s in namespace %s for attestation verification", a.KeyID, ns)
			continue
		}
		if err = h.VerifyAttestationSignature(s.PublicKey, a.Signature); err != nil {
			glog.Errorf("could not find verify attestation for attestation authority %s", a.KeyID)
		} else {
			return true
		}
	}
	return false
}
