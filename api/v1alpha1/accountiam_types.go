/*
Copyright 2025.

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

package v1alpha1

import (
	odlm "github.com/IBM/operand-deployment-lifecycle-manager/v4/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AccountIAM Phase constants (CR lifecycle phases)
const (
	PhaseInitializing = "Initializing"
	PhaseCreating     = "Creating"
	PhasePending      = "Pending"
	PhaseRunning      = "Running"
	PhaseReady        = "Ready"
	PhaseFailed       = "Failed"
	PhaseError        = "Error"
)

// Resource Status constants (individual resource states)
const (
	StatusReady     = "Ready"
	StatusNotReady  = "NotReady"
	StatusPending   = "Pending"
	StatusCompleted = "Completed"
	StatusFailed    = "Failed"
	StatusError     = "Error"
	StatusNotFound  = "NotFound"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AccountIAMSpec defines the desired state of AccountIAM
type AccountIAMSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of AccountIAM. Edit accountiam_types.go to remove/update
	Foo string `json:"foo,omitempty"`
}

// // ManagedResourceStatus represents the status of a resource managed by AccountIAM
// type ManagedResourceStatus struct {
// 	ObjectName string `json:"objectName,omitempty"`
// 	APIVersion string `json:"apiVersion,omitempty"`
// 	Namespace  string `json:"namespace,omitempty"`
// 	Kind       string `json:"kind,omitempty"`
// 	Status     string `json:"status,omitempty"`
// }

// // ServiceStatus represents the status of the AccountIAM service and its managed resources
// type ServiceStatus struct {
// 	ObjectName       string                  `json:"objectName,omitempty"`
// 	APIVersion       string                  `json:"apiVersion,omitempty"`
// 	Namespace        string                  `json:"namespace,omitempty"`
// 	Kind             string                  `json:"kind,omitempty"`
// 	Status           string                  `json:"status,omitempty"`
// 	ManagedResources []ManagedResourceStatus `json:"managedResources,omitempty"`
// }

// AccountIAMStatus defines the observed state of AccountIAM
type AccountIAMStatus struct {
	// Phase represents the current phase of the AccountIAM lifecycle
	// +kubebuilder:validation:Enum=Initializing;Creating;Pending;Running;Ready;Failed;Error
	Phase string `json:"phase,omitempty"`

	// Import the operandstatus from odlm
	Service odlm.OperandStatus `json:"service,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// AccountIAM is the Schema for the accountiams API
type AccountIAM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AccountIAMSpec   `json:"spec,omitempty"`
	Status AccountIAMStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AccountIAMList contains a list of AccountIAM
type AccountIAMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccountIAM `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AccountIAM{}, &AccountIAMList{})
}
