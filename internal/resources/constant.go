//
// Copyright 2024 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package resources

const (
	// Default User Management CR
	UserMgmtCR = "AccountIAM"
	// Default OperandRequest
	UserMgmtOpreq = "user-management-request"
	// OpreqKind is the kind of OperandConfig
	OpreqKind = "OperandRequest"
	// OperandStatusRedy is the Ready status of Operand
	OperandStatusRedy = "Ready"
	// WebSphere is the name of WebSphere Operator
	WebSpherePackage = "ibm-websphere-liberty"
	// WebSphereAPIGroupVersion is the api group version of WebSphereLibertyApplication
	WebSphereAPIGroupVersion = "liberty.websphere.ibm.com/v1"
	// WebSphereKind is the kind of WebSphereLibertyApplication
	WebSphereKind = "WebSphereLibertyApplication"
	// IMPackage is the name of IM Operator
	IMPackage = "ibm-im-operator"
	// EDBAPIGroupVersion is the api group version of Cluster
	EDBAPIGroupVersion = "postgresql.k8s.enterprisedb.io/v1"
	// EDBClusterKind is the kind of Cluster
	EDBClusterKind = "Cluster"
	// IMConfigJob is the name of the IM configuration job
	IMConfigJob = "mcsp-im-config-job"
)
