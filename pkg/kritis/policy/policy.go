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

package policy

// Reason defines the Violation Reason
type Reason string

// Violation defines the policy violation
type Violation struct {
	Image     string
	Violation int
	Reason    Reason
}

// A list of security policy violations
// TODO: Add Attestation checking violations
const (
	UnqualifiedImageViolation int = iota
	FixUnavailableViolation
	SeverityViolation
)
