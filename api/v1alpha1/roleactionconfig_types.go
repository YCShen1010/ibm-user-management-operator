/*
Copyright 2024.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// RoleActionConfigSpec defines the desired state of RoleActionConfig
type RoleActionConfigSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	ServiceID string `json:"serviceID"`

	IAM IAM `json:"IAM,omitempty"`
}

type IAM struct {
	// +optional
	V2 bool `json:"v2"`
	// +optional
	ClientID string `json:"clientID,omitempty"`
	// +optional
	V2CustomRoles []V2CustomRoles `json:"v2CustomRoles,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Actions []string `json:"actions,omitempty"`
}

type V2CustomRoles struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Actions []string `json:"actions,omitempty"`
}

// RoleActionConfigStatus defines the observed state of RoleActionConfig
type RoleActionConfigStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// RoleActionConfig is the Schema for the roleactionconfigs API
type RoleActionConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RoleActionConfigSpec   `json:"spec,omitempty"`
	Status RoleActionConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RoleActionConfigList contains a list of RoleActionConfig
type RoleActionConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RoleActionConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RoleActionConfig{}, &RoleActionConfigList{})
}
