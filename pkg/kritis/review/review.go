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

	"github.com/golang/glog"
	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"github.com/grafeas/kritis/pkg/kritis/violation"
	"k8s.io/api/core/v1"
)

// Config defines the configurations required for review process.
type Config struct {
	ValidateImageSecurityPolicy func(isp kritisv1beta1.ImageSecurityPolicy, image string, client metadata.MetadataFetcher) ([]securitypolicy.SecurityPolicyViolation, error)
	ValidateAttestations        func(image string, mClient metadata.MetadataFetcher, ns string, fetcher secrets.Fetcher) bool
	FullVerification            bool
}

type Reviewer struct {
	client metadata.MetadataFetcher
	vs     violation.Strategy
}

func New(client metadata.MetadataFetcher, vs violation.Strategy) Reviewer {
	return Reviewer{
		client: client,
		vs:     vs,
	}
}

// Review reviews a given images against ImageSecurityPolicies and return error
// if voilations are found and handles violation as per violation strategy
// Returns true/false if no voilations present or e
func (r Reviewer) Review(images []string, isps []kritisv1beta1.ImageSecurityPolicy, pod *v1.Pod, config Config) error {
	images = util.GetUniqueImages(images)
	images = util.RemoveGloballyWhitelistedImages(images)
	if len(images) == 0 {
		glog.Infof("images are all globally whitelisted, returning successful status", images)
		return nil
	}

	for _, isp := range isps {
		for _, image := range images {
			glog.Infof("Check if %s as valid Attestations.", image)
			isAttested := config.ValidateAttestations(image, r.client, isp.Namespace, secrets.FetchSecret)
			if err := r.vs.HandleAttestation(image, pod, isAttested); err != nil {
				return fmt.Errorf("error handling attestations %v", err)
			}
			if isAttested && !config.FullVerification {
				continue
			}
			glog.Infof("Getting vulnz for %s", image)
			violations, err := config.ValidateImageSecurityPolicy(isp, image, r.client)
			if err != nil {
				return fmt.Errorf("error validating image security policy %v", err)
			}
			// Check if one of the violations is that the image is not fully qualified
			for _, v := range violations {
				if v.Violation == securitypolicy.UnqualifiedImageViolation {
					return fmt.Errorf("%s is not a fully qualified image", image)
				}
			}
			if len(violations) != 0 {
				if err := r.vs.HandleViolation(image, pod, violations); err != nil {
					return fmt.Errorf("found violations in %s. error handling voilation %v", image, err)
				}
				return fmt.Errorf("found violations in %s", image)
			}
		}
	}
	return nil
}

// HasValidImageAttestations return true if any one image attestation is verified.
func HasValidImageAttestations(image string, client metadata.MetadataFetcher, ns string, fetcher secrets.Fetcher) bool {
	host, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		glog.Info(err)
		return false
	}
	attestations, err := client.GetAttestations(image)
	if err != nil {
		glog.Infof("Error while fetching attestations %s", err)
		return false
	}
	if len(attestations) == 0 {
		glog.Infof(`No attestations found for this image.
This normally happens when you deploy a pod before kritis or no attestation authority is deployed.
Please see instructions `)
	}
	for _, a := range attestations {
		// Get Secret from key id.
		secret, err := fetcher(ns, a.KeyId)
		if err != nil {
			glog.Infof("Could not find secret %s in namespace %s for attestation verification", a.KeyId, ns)
			continue
		}
		if err = host.VerifyAttestationSignature(secret.PublicKey, a.Signature); err != nil {
			glog.Infof("Could not find verify attestation for attestation authority %s", a.KeyId)
		} else {
			return true
		}
	}
	return false
}
