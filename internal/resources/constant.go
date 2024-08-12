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
	UserMgmtOpreq = "ibm-user-management-request"
	// OpreqKind is the kind of OperandConfig
	OpreqKind = "OperandRequest"
	// WebSphere is the name of WebSphere Operator
	WebSpherePackage = "ibm-websphere-liberty"
	// WebSphereAPIGroupVersion is the api group version of WebSphereLibertyApplication
	WebSphereAPIGroupVersion = "liberty.websphere.ibm.com/v1"
	// WebSphereKind is the kind of WebSphereLibertyApplication
	WebSphereKind = "WebSphereLibertyApplication"
	// RedisOperator is the subscription name of Redis Operator
	RedisOperator = "ibm-redis-cp-operator"
	// Rediscp is the name of Redis CR
	Rediscp = "account-iam-ui-redis"
	// RedisKind is the kind of Redis
	RedisKind = "Rediscp"
	// RedisAPIGroup is the api group of Redis
	RedisAPIGroup = "redis.ibm.com"
	// RedisVersion is the version of Redis
	RedisVersion = "v1"
	//RedisURLssl
	RedisURLssl = "redis-url-ssl"
	// RedisURL is the Certificate of Redis
	RedisCert = "account-iam-ui-redis-cert"
	// RedisCertKey is the key of Redis CA Certificate
	RedisCertKey = "cacertb64.pem"
	// OpreqPhaseRunning is the Running status of Operand
	OpreqPhaseRunning = "Running"
	// OperandStatusReady is the Ready status of Operand
	OperandStatusReady = "Ready"
	// OperandStatusComp is the Completed status of Operand
	OperandStatusComp = "Completed"
	// IMPackage is the name of IM Operator
	IMPackage = "ibm-im-operator"
	// EDBClusterKind is the kind of Cluster
	EDBClusterKind = "Cluster"
	// EDBAPIGroupVersion is the api group version of Cluster
	EDBAPIGroupVersion = "postgresql.k8s.enterprisedb.io/v1"
	// CreateDBJob is the name of the database creation job
	CreateDBJob = "create-account-iam-db"
	// DBMigrationJob is the name of the database migration job
	DBMigrationJob = "account-iam-db-migration-mcspid"
	// IMConfigJob is the name of the IM configuration job
	IMConfigJob = "mcsp-im-config-job"
	// IMOIDCCrendential is the secret where the IM OIDC credential is stored
	IMOIDCCrendential = "ibm-iam-bindinfo-platform-oidc-credentials"
	// WLPClientID is the key in the secret.data where the WLP client ID is stored
	WLPClientID = "WLP_CLIENT_ID"
	// IMAPISecret is the secret where the IM API key is stored
	IMAPISecret = "mcsp-im-integration-details"
	// IMAPIKey is the key in the secret.data where the IM API key is stored
	IMAPIKey = "API_KEY"
)
