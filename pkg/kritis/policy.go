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
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"k8s.io/api/core/v1"
)

// Policy defines a policy enforced by Kritis.
type Policy interface {
	// Reviews a set of images against the policy.
	Review(ns string, images []string, client metadata.Fetcher, pod *v1.Pod) ([]Violation, error)
	// HasValidAttestations checks if a policy has any attestations
	HasValidAttestations(ns string, images []string) bool
	// Attest a set of with required attestations.
	Attest(ns string, images []string, client metadata.Fetcher) error
	// Annotation returns a string annotation value for given violation.
	Annotate([]Violation) string
	// Name
	Name() string
}

type Violation interface {
}
