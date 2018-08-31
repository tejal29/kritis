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
	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/policy"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"k8s.io/api/core/v1"
)

// Policy defines Image Security Policy
type Policy struct {
}

// For testing
var (
	authFetcher   = authority.Authorities
	ispFetcher    = securitypolicy.ImageSecurityPolicies
	secretFetcher = secrets.Fetch
	validate      = securitypolicy.ValidateImageSecurityPolicy
)

// Review reviews an image against ImageSecurityPolicy and attests
// an image if its valid.
func (p Policy) Review(ns string, images []string, client metadata.Fetcher, pod *v1.Pod) ([]policy.Violation, error) {
	isps, err := ispFetcher(ns)
	if err != nil {
		return nil, err
	}
	images = util.RemoveGloballyWhitelistedImages(images)
	if len(images) == 0 {
		glog.Info("images are all globally whitelisted, returning successful status", images)
		return nil, nil
	}
	for _, isp := range isps {
		glog.Infof("Validating image %s", isp.Name)
		for _, image := range images {
			// Check if attestations exist for the given policy
			if hasValidImageAttestations(image, ns, client) {
				continue
			} else {
				//  if err := r.config.Strategy.HandleAttestation(images, pod, isAttested); err != nil {
				glog.Errorf("error handling attestations %v", err)
				//}
			}
			glog.Infof("Getting vulnz for %s", image)
			if violations, err := validate(isp, image, client); err != nil || len(violations) != 0 {
				return violations, err
			}
			glog.Infof("Found no violations in %s", image)
		}
	}
	return nil, nil
}

// Name returns the name of this policy
func (p Policy) Name() string {
	return "ImageSecurityPolicy"
}

func hasValidImageAttestations(image string, ns string, client metadata.Fetcher) bool {
	attestations, err := client.GetAttestations(image)
	if err != nil {
		glog.Errorf("Error while fetching attestations %s", err)
		return false
	}
	if len(attestations) == 0 {
		glog.Infof(`No attestations found for image %s.
This normally happens when you deploy a pod before kritis or no attestation authority is deployed.
Please see instructions to %s`, image, constants.Tutorial)
	}
	host, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		glog.Error(err)
		return false
	}
	for _, a := range attestations {
		// Get Secret from key id.
		secret, err := secretFetcher(ns, a.KeyID)
		if err != nil {
			glog.Errorf("Could not find secret %s in namespace %s for attestation verification", a.KeyID, ns)
			continue
		}
		if err = host.VerifyAttestationSignature(secret.PublicKey, a.Signature); err != nil {
			glog.Errorf("Could not find verify attestation for attestation authority %s", a.KeyID)
		} else {
			return true
		}
	}
	return false
}

func getUnAttested(auths []v1beta1.AttestationAuthority, atts []metadata.PGPAttestation) []v1beta1.AttestationAuthority {
	l := []v1beta1.AttestationAuthority{}
	m := map[string]bool{}
	for _, a := range atts {
		m[a.KeyID] = true
	}

	for _, a := range auths {
		_, ok := m[a.Spec.PrivateKeySecretName]
		if !ok {
			l = append(l, a)
		}
	}
	return l
}
