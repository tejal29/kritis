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
	"fmt"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/kubectl/plugins/resolve"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	ca "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
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
	validate      = ValidateImageSecurityPolicy
)

// Review reviews an image against ImageSecurityPolicy and attests
// an image if its valid.
func (p Policy) Review(ns string, images []string, client metadata.Fetcher, pod *v1.Pod) ([]Violation, error) {
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
	attestations, err := client.Attestations(image)
	if err != nil {
		glog.Errorf("Error while fetching attestations %s", err)
		return false
	}
	if len(attestations) == 0 {
		glog.Infof(`No attestations found for image %s.
This normally happens when you deploy a pod before kritis or no attestation authority is deployed.
Please see instructions to https://github.com/grafeas/kritis/blob/master/tutorial.md#2-setting-up-an-attestationauthority`, image)
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

// ValidateImageSecurityPolicy checks if an image satisfies ISP requirements
// It returns a list of vulnerabilities that don't pass
func ValidateImageSecurityPolicy(isp v1beta1.ImageSecurityPolicy, image string, client metadata.Fetcher) ([]Violation, error) {
	// First, check if image is whitelisted
	if imageInWhitelist(isp, image) {
		return nil, nil
	}
	var violations []Violation
	// Next, check if image in qualified
	if !resolve.FullyQualifiedImage(image) {
		violations = append(violations, Violation{
			Violation: UnqualifiedImageViolation,
			Reason:    UnqualifiedImageReason(image),
		})
		return violations, nil
	}
	// Now, check vulnz in the image
	vulnz, err := client.Vulnerabilities(image)
	if err != nil {
		return nil, err
	}
	maxSev := isp.Spec.PackageVulnerabilityRequirements.MaximumSeverity
	if maxSev == "" {
		maxSev = "CRITICAL"
	}

	maxNoFixSev := isp.Spec.PackageVulnerabilityRequirements.MaximumFixUnavailableSeverity
	if maxNoFixSev == "" {
		maxNoFixSev = "ALLOW_ALL"
	}

	for _, v := range vulnz {
		// First, check if the vulnerability is whitelisted
		if cveInWhitelist(isp, v.CVE) {
			continue
		}

		// Allow operators to set a higher threshold for CVE's that have no fix available.
		if !v.HasFixAvailable {
			ok, err := severityWithinThreshold(maxNoFixSev, v.Severity)
			if err != nil {
				return violations, err
			}
			if ok {
				continue
			}
			violations = append(violations, Violation{
				Vulnerability: v,
				Violation:     FixUnavailableViolation,
				Reason:        FixUnavailableReason(image, v, isp),
			})
			continue
		}
		ok, err := severityWithinThreshold(maxSev, v.Severity)
		if err != nil {
			return violations, err
		}
		if ok {
			continue
		}
		violations = append(violations, Violation{
			Vulnerability: v,
			Violation:     SeverityViolation,
			Reason:        SeverityReason(image, v, isp),
		})
	}
	return violations, nil
}

func imageInWhitelist(isp v1beta1.ImageSecurityPolicy, image string) bool {
	for _, i := range isp.Spec.ImageWhitelist {
		if i == image {
			return true
		}
	}
	return false
}

func cveInWhitelist(isp v1beta1.ImageSecurityPolicy, cve string) bool {
	for _, w := range isp.Spec.PackageVulnerabilityRequirements.WhitelistCVEs {
		if w == cve {
			return true
		}
	}
	return false
}

func severityWithinThreshold(maxSeverity string, severity string) (bool, error) {
	if maxSeverity == constants.BlockAll {
		return false, nil
	}
	if maxSeverity == constants.AllowAll {
		return true, nil
	}
	if _, ok := ca.VulnerabilityType_Severity_value[maxSeverity]; !ok {
		return false, fmt.Errorf("invalid max severity level: %s", maxSeverity)
	}
	if _, ok := ca.VulnerabilityType_Severity_value[severity]; !ok {
		return false, fmt.Errorf("invalid severity level: %s", severity)
	}
	return ca.VulnerabilityType_Severity_value[severity] <= ca.VulnerabilityType_Severity_value[maxSeverity], nil
}
