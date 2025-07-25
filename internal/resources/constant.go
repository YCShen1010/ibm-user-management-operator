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
	// UserMgmtOperator is the subscription name of User Management Operator
	UserMgmtOperator = "ibm-user-management-operator"
	// OperatorIBMApiVersion is the api version of IBM Operator
	OperatorIBMApiVersion = "operator.ibm.com/v1alpha1"
	// Default OperandRequest
	UserMgmtOpreq = "ibm-user-management-request"
	// OpreqKind is the kind of OperandConfig
	OpreqKind = "OperandRequest"
	// SericeKind is the kind of Service
	ServiceKind = "Service"
	// SecretKind is the kind of Secret
	SecretKind = "Secret"
	// RouteKind is the kind of Route
	RouteKind = "Route"
	// RouteAPIGroup is the api group of Route
	RouteAPIGroup = "route.openshift.io"
	// Version is the version of some resources
	Version = "v1"
	// JobKind is the kind of Job
	JobKind = "Job"
	// JobAPIGroup is the api group of Job
	JobAPIGroup = "batch/v1"
	//AccountIAM is the name of the Account IAM resources
	AccountIAM = "account-iam"
	// CSCASecret is the name of the secret for CA certificate
	CSCASecret = "cs-ca-certificate-secret"
	// RedisCertKey is the key of Redis CA Certificate
	CAKey = "ca.crt"
	// RedisOperator is the subscription name of Redis Operator
	RedisOperator = "ibm-redis-cp-operator"
	// Rediscp is the name of Redis CR
	Rediscp = "account-iam-ui-redis"
	// RedisKind is the kind of Redis
	RedisKind = "Rediscp"
	// RedisAPIGroup is the api group of Redis
	RedisAPIGroup = "redis.ibm.com"
	// RedisStatus is the status field in Redis CR
	RedisStatus = "redisStatus"
	//RedisURLssl
	RedisURLssl = "redis-url-ssl"
	//RedisPassword
	RedisPassword = "auth"
	// RedisCert is the name of Redis CA Certificate and secret
	RedisCACert = "account-iam-ui-redis-ca-cert"
	// RedisCert is the name of Redis service Certificate and secret
	RedisSVCCert = "account-iam-ui-redis-svc-tls-cert"
	// PhaseRunning is the Running status
	PhaseRunning = "Running"
	// StatusCompleted is the Completed status
	StatusCompleted = "Completed"
	// StatusReady is the Ready status
	StatusReady = "Ready"
	// StatusNotReady is the NotReady status
	StatusNotReady = "NotReady"
	// StatusNotFound is the NotFound status
	StatusNotFound = "NotFound"
	// StatusPending is the Pending status
	StatusPending = "Pending"
	// StatusFailed is the Failed status
	StatusFailed = "Failed"
	// StatusError is the Error status
	StatusError = "Error"
	// IMPackage is the name of IM Operator
	IMPackage = "ibm-im-operator"
	// EDBClusterKind is the kind of Cluster
	EDBClusterKind = "Cluster"
	// EDBAPIGroupVersion is the api group version of Cluster
	EDBAPIGroupVersion = "postgresql.k8s.enterprisedb.io/v1"
	// BootstrapSecret is the name of the secret for user management bootstrap
	BootstrapSecret = "user-mgmt-bootstrap"
	// CreateDBJob is the name of the database creation job
	CreateDBJob = "create-account-iam-db"
	// DBMigrationJob is the name of the database migration job
	DBMigrationJob = "account-iam-db-migration-mcspid"
	// AccountIAMDBSecret is the name of the secret for Account IAM database
	AccountIAMDBSecret = "account-iam-database-secret"
	// AccountIAMConfigSecret is the name of the secret for Account IAM mpconfig
	AccountIAMConfigSecret = "account-iam-mpconfig-secrets"
	// AccountIAMOidcClientAuth is the name of the secret for Account IAM OIDC client auth
	AccountIAMOidcClientAuth = "account-iam-oidc-client-auth"
	// AccountIAMOKDAuth is the name of the secret for Account IAM OKD auth
	AccountIAMOKDAuth = "account-iam-okd-auth"
	// AccountIAMUISecrets is the name of the secret for Account IAM UI config
	AccountIAMUISecrets = "account-iam-ui-secrets"
	// AccountIAMUIRoute is the name of the route for Account IAM UI
	AccountIAMUIRoute = "account-iam-ui-account"
	// AccountIAMUIAPIInstance is the name of the API instance for Account IAM UI
	AccountIAMUIAPIInstance = "account-iam-ui-api-instance"
	// AccountIAMUIAPIService is the name of the API service for Account IAM UI
	AccountIAMUIAPIService = "account-iam-ui-api-service"
	//	AccountIAMUIService is the name of the Account service for Account IAM UI
	AccountIAMUIService = "account-iam-ui-account-service"
	// AccountIAMCACert is the name of the Account IAM CA certificate and secret
	AccountIAMCACert = "account-iam-ca-cert"
	// AccountIAMSVCCert is the name of the Account IAM service certificate and secret
	AccountIAMSVCCert = "account-iam-svc-tls-cert"
	// IMConfigJob is the name of the IM configuration job
	IMConfigJob = "mcsp-im-config-job"
	// IMOIDCCrendential is the secret where the IM OIDC credential is stored
	IMOIDCCrendential = "ibm-iam-bindinfo-platform-oidc-credentials"
	// IMPlatformCM is the configmap where the auth idp related information is stored
	IMPlatformCM = "platform-auth-idp"
	// WLPClientID is the key in the secret.data where the WLP client ID is stored
	WLPClientID = "WLP_CLIENT_ID"
	// IMAPISecret is the secret where the IM API key is stored
	IMAPISecret = "mcsp-im-integration-details"
	// MCSPAPIKey is the MCSP API key generated by calling MCSP API Key Management API
	MCSPAPIKey = "API_KEY"
	// SkipAnnotations is the annotation to skip the update of the operand resrouces
	SkipAnnotation = "operator.ibm.com/ibm-user-management-operator.skip-update"
	//HashedData is the key for checking the checksum of data section
	HashedData string = "operator.ibm.com/ibm-user-management-operator.hashedData"
)
