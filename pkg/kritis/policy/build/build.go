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

package build

import (
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/crd/buildpolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"k8s.io/api/core/v1"
)

func requiredAttestations(bps []v1beta1.BuildPolicy) map[string]bool {
	m := map[string]bool{}
	for _, bp := range bps {
		m[bp.Spec.AttestationAuthorityName] = true
	}
	return m
}

// Name returns the name of this policy
func (p Policy) Name() string {
	return "BuildAttestation"
}

// Policy defines Build Policy
type Policy struct {
}

// Review reviews an image against ImageSecurityPolicy and attests
// an image if its valid.
func (p Policy) Review(ns string, images []string, client metadata.Fetcher, pod *v1.Pod) ([]kritis.Violation, error) {
	bps, err := buildpolicy.BuildPolicies(ns)
	vs := []buildpolicy.Violation{}
	if err != nil {
		return nil, fmt.Errorf("error retrieving build policies: %v", err)
	}
	for _, i := range images {
		host, err := container.NewAtomicContainerSig(i, map[string]string{})
		if err != nil {
			return nil, err
		}
		attestations, err := client.GetAttestations(i)
		if err != nil {
			return nil, fmt.Errorf("error while fetching attestations %s", err)
		}
		// BuildPolicy specifies the attestation authority.
		// Verify all these attestations.
		aMap := requiredAttestations(bps)
		if !util.HasAllValidHostSignature(host, attestations, ns, aMap, secrets.Fetch) {
			return fmt.Errorf("could not verify signature for image %s", i)
		}
	}
	return nil
}
