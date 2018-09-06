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

package kritis

import (
	"fmt"
	"strings"

	"github.com/golang/glog"

	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"k8s.io/api/core/v1"
)

// Reviewer defines reviewer struct
type Reviewer struct {
	config *ReviewConfig
	client metadata.Fetcher
}

// ReviewConfig defines ReviewConfig
type ReviewConfig struct {
	Strategy  Strategy
	IsWebhook bool
}

// New creates a New Reviewer Object with given Config
func New(client metadata.Fetcher, c *ReviewConfig) Reviewer {
	return Reviewer{
		client: client,
		config: c,
	}
}

// Review reviews a set of images against a set of policies
// Returns error if violations are found and handles them as per violation strategy
func (r Reviewer) Review(images []string, pod *v1.Pod, ps []Policy) error {
	errMsgs := []string{}
	for _, p := range ps {
		vs, err := p.Review(pod.Namespace, images, r.client, pod)
		if err != nil {
			errMsgs = append(errMsgs, fmt.Sprintf("error reviewing %s %v", p.Name(), err))
		}
		if len(vs) != 0 {
			r.config.Strategy.HandleViolations(pod, vs)
		}
		if r.config.IsWebhook {
			if err := p.Attest(pod.Namespace, images, r.client); err != nil {
				glog.Errorf("error adding attestations %s", err)
			}
		}
	}
	if len(errMsgs) > 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (r Reviewer) handleViolations(image string, pod *v1.Pod, violations []Violation) error {
	errMsg := fmt.Sprintf("found violations in %s", image)
	// Check if one of the violations is that the image is not fully qualified
	for _, v := range violations {
		if v.Violation == UnqualifiedImageViolation {
			errMsg = fmt.Sprintf(`%s is not a fully qualified image.
			  You can run 'kubectl plugin resolve-tags' to qualify all images with a digest.
			  Instructions for installing the plugin can be found at https://github.com/grafeas/kritis/blob/master/cmd/kritis/kubectl/plugins/resolve`, image)
		}
	}
	if err := r.config.Strategy.HandleViolations(pod, violations); err != nil {
		return fmt.Errorf("%s. error handling violation %v", errMsg, err)
	}
	return fmt.Errorf(errMsg)
}

// // Attest images
// func (r Reviewer) Attest(images []string) error {
// 	// Get all AttestationAuthorities in this namespace.
// 	auths, err := authFetcher(ns)
// 	if err != nil {
// 		return err
// 	}
// 	if len(auths) == 0 {
// 		return fmt.Errorf("no attestation authorities configured for namespace %s", ns)
// 	}
// 	// Get all AttestationAuthorities which have not attested the image.
// 	errMsgs := []string{}
// 	u := getUnAttested(auths, atts)
// 	if len(u) == 0 {
// 		glog.Info("Attestation exists for all authorities")
// 		return nil
// 	}
// 	for _, a := range u {
// 		// Get or Create Note for this this Authority
// 		n, err := util.GetOrCreateAttestationNote(r.client, &a)
// 		if err != nil {
// 			errMsgs = append(errMsgs, err.Error())
// 		}
// 		// Get secret for this Authority
// 		s, err := r.config.Secret(ns, a.Spec.PrivateKeySecretName)
// 		if err != nil {
// 			errMsgs = append(errMsgs, err.Error())
// 		}
// 		// Create Attestation Signature
// 		if _, err := client.CreateAttestationOccurence(n, image, s); err != nil {
// 			errMsgs = append(errMsgs, err.Error())
// 		}
// 	}
// 	if len(errMsgs) == 0 {
// 		return nil
// 	}
// 	return fmt.Errorf("one or more errors adding attestations: %s", errMsgs)
// }
