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
package violation

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/pods"
	"github.com/grafeas/kritis/pkg/kritis/policy"
	"k8s.io/api/core/v1"
)

type Strategy interface {
	HandleViolations(pod *v1.Pod, violations []policy.Violation) error
	HandleAttestation(images string, pod *v1.Pod, isAttested bool) error
}

type LoggingStrategy struct {
}

func (l *LoggingStrategy) HandleViolations(pod *v1.Pod, vs []policy.Violation) error {
	glog.Info("HandleViolation via LoggingStrategy")
	if len(vs) == 0 {
		return nil
	}
	for _, v := range vs {
		glog.Warning("Found violation in image %s %s", v.Image, v.Reason)
	}
	return nil
}

func (l *LoggingStrategy) HandleAttestation(images []string, pod *v1.Pod, isAttested bool) error {
	glog.Info("Handling attestation via LoggingStrategy")
	if isAttested {
		glog.Infof("Image %s has one or more valid attestation(s)", images)
	} else {
		glog.Infof("No Valid Attestations Found for image %s. Proceeding with next checks", images)
	}
	return nil
}

// AnnotationStrategy adds "InvalidImageSecPolicy" as a label and an annotation, with detailed info in the annotations
type AnnotationStrategy struct {
}

func (a *AnnotationStrategy) HandleViolations(pod *v1.Pod, violations []policy.Violation) error {
	// First, remove "kritis.grafeas.io/invalidImageSecPolicy" label/annotation in case it doesn't apply anymore
	if err := pods.DeleteLabelsAndAnnotations(*pod, []string{constants.InvalidImageSecPolicy}, []string{constants.InvalidImageSecPolicy}); err != nil {
		return err
	}
	if len(violations) == 0 {
		return nil
	}
	// Now, construct labels and annotations
	labelValue := constants.InvalidImageSecPolicyLabelValue
	annotationValue := fmt.Sprintf("found %d CVEs", len(violations))
	// for _, v := range violations {
	// 	if v.Violation == kritis.UnqualifiedImageViolation {
	// 		annotationValue += fmt.Sprintf(", %s", v.Reason)
	// 		break
	// 	}
	// }
	labels := map[string]string{constants.InvalidImageSecPolicy: labelValue}
	annotations := map[string]string{constants.InvalidImageSecPolicy: annotationValue}
	glog.Info(fmt.Sprintf("Adding label %s and annotation %s", labelValue, annotationValue))
	return pods.AddLabelsAndAnnotations(*pod, labels, annotations)
}

func (a *AnnotationStrategy) HandleAttestation(images []string, pod *v1.Pod, isAttested bool) error {
	// First, remove "kritis.grafeas.io/attestation" label/annotation in case it doesn't apply anymore
	if err := pods.DeleteLabelsAndAnnotations(*pod, []string{constants.ImageAttestation}, []string{constants.ImageAttestation}); err != nil {
		return err
	}
	lValue := constants.NoAttestationsLabelValue
	aValue := constants.NoAttestationsAnnotation
	if isAttested {
		lValue = constants.PreviouslyAttestedLabelValue
		aValue = constants.PreviouslyAttestedAnnotation
	}
	labels := map[string]string{constants.ImageAttestation: lValue}
	annotations := map[string]string{constants.ImageAttestation: aValue}
	glog.Info(fmt.Sprintf("Adding label %s and annotation %s", lValue, aValue))
	return pods.AddLabelsAndAnnotations(*pod, labels, annotations)
}

// For unit testing.
type MemoryStrategy struct {
	Violations   map[string]bool
	Attestations map[string]bool
}

func (ms *MemoryStrategy) HandleViolations(image string, p *v1.Pod, v []policy.Violation) error {
	ms.Violations[image] = true
	return nil
}

func (ms *MemoryStrategy) HandleAttestation(image string, pod *v1.Pod, isAttested bool) error {
	ms.Attestations[image] = isAttested
	return nil
}
