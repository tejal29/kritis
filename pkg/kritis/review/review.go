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
	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/violation"
	"k8s.io/api/core/v1"
)

type Reviewer struct {
	config *Config
	client metadata.Fetcher
}

type Config struct {
	Strategy  violation.Strategy
	IsWebhook bool
	Policies  []kritis.Policy
}

func New(client metadata.Fetcher, c *Config) Reviewer {
	return Reviewer{
		client: client,
		config: c,
	}
}

// For testing
var (
	authFetcher = authority.Authorities
)

func (r Reviewer) Review(namespace string, images []string, pod *v1.Pod) []error {
	errors := []error{}
	for _, p := range r.config.Policies {
		// Review each policy
		vs, err := p.Review(namespace, images, r.client, pod)
		if err != nil {
			errors = append(errors, err)
		}
		// Handle the violations using the Strategy configured
		if len(vs) != 0 {
			if err := r.config.Strategy.HandleViolations(pod, vs); err != nil {
				glog.Errorf("error handling violations %v", err)
			}
		} else {
			// Attest the image with right attestation authorities
		}
	}
	return errors
}
