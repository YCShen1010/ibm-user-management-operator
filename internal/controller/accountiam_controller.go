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

package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"text/template"
	"time"

	certmgrv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	routev1 "github.com/openshift/api/route/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	operatorv1alpha1 "github.com/IBM/ibm-user-management-operator/api/v1alpha1"
	"github.com/IBM/ibm-user-management-operator/internal/controller/utils"
	"github.com/IBM/ibm-user-management-operator/internal/resources"
	res "github.com/IBM/ibm-user-management-operator/internal/resources/yamls"
	odlm "github.com/IBM/operand-deployment-lifecycle-manager/v4/api/v1alpha1"
	"github.com/ghodss/yaml"
)

// AccountIAMReconciler reconciles a AccountIAM object
type AccountIAMReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Config   *rest.Config
	Recorder record.EventRecorder
}

// BootstrapSecret stores all the bootstrap secret data
type BootstrapSecret struct {
	Realm               string
	ClientID            string
	ClientSecret        string
	PGPassword          string
	DefaultAUDValue     string
	DefaultRealmValue   string
	SREMCSPGroupsToken  string
	GlobalRealmValue    string
	GlobalAccountAud    string
	UserValidationAPIV2 string
}

var BootstrapData BootstrapSecret

// BootstrapSecret stores all the bootstrap secret data
type IntegrationConfig struct {
	DiscoveryEndpoint    string
	DefaultIDPValue      string
	GlobalAccountIDP     string
	IMURL                string
	AccountIAMURL        string
	AccountIAMConsoleURL string
	AccountIAMNamespace  string
}

var IntegrationData IntegrationConfig

// RouteData holds the parameters for the Route CR
type RouteParams struct {
	CAcert string
}

var RouteData RouteParams

// RedisCRParams holds the parameters for the Redis CR
type RedisCRParams struct {
	RedisCRSize    int
	RedisCRVersion string
}

var RedisCRData RedisCRParams

type UIBootstrapTemplate struct {
	Hostname                    string
	InstanceManagementHostname  string
	NodeEnv                     string
	CertDir                     string
	ConfigEnv                   string
	RedisHost                   string
	AccountAPI                  string
	ProductAPI                  string
	MeteringAPI                 string
	InstanceAPI                 string
	IssuerBaseURL               string
	SubscriptionAPI             string
	APIOAUTHTokenURL            string
	RedisCA                     string
	ClientID                    string
	ClientSecret                string
	DisableRedis                string
	SessionSecret               string
	DeploymentCloud             string
	IAMGlobalAPIKey             string
	APIOAUTHClientID            string
	APIOAUTHClientSecret        string
	IAMAPI                      string
	MyIBMURL                    string
	AWSProvisioningURL          string
	IBMCloudProvisioningURL     string
	ProductRegistrationUsername string
	ProductRegistrationPassword string
	IMIDMgmt                    string
	CSIDPURL                    string
	DefaultAccount              string
	DefaultInstance             string
}

var UIBootstrapData UIBootstrapTemplate

//+kubebuilder:rbac:groups=operator.ibm.com,namespace="placeholder",resources=accountiams,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.ibm.com,namespace="placeholder",resources=accountiams/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=operator.ibm.com,namespace="placeholder",resources=accountiams/finalizers,verbs=update
//+kubebuilder:rbac:groups=operator.ibm.com,namespace="placeholder",resources=operandrequests,verbs=get;list;watch;create
//+kubebuilder:rbac:groups=redis.ibm.com,namespace="placeholder",resources=rediscps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=route.openshift.io,namespace="placeholder",resources=routes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=route.openshift.io,namespace="placeholder",resources=routes/custom-host,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,namespace="placeholder",resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",namespace="placeholder",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",namespace="placeholder",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",namespace="placeholder",resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=batch,namespace="placeholder",resources=jobs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",namespace="placeholder",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,namespace="placeholder",resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,namespace="placeholder",resources=rolebindings;roles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.openshift.io,resources=securitycontextconstraints,verbs=use
//+kubebuilder:rbac:groups=cert-manager.io,namespace="placeholder",resources=issuers;certificates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",namespace="placeholder",resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=coordination.k8s.io,namespace="placeholder",resources=leases,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the AccountIAM object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.3/pkg/reconcile
func (r *AccountIAMReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	klog.Infof("Reconciling AccountIAM using fid image")

	instance := &operatorv1alpha1.AccountIAM{}
	err := r.Client.Get(context.TODO(), req.NamespacedName, instance)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			klog.Infof("CR instance not found, don't requeue")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	if err := r.verifyPrereq(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileOperandResources(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.configIM(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileUI(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	klog.Infof("Reconcile completed successfully for AccountIAM CR %s/%s", instance.Namespace, instance.Name)
	return ctrl.Result{}, nil
}

// -------------- verifyPrereq helper functions --------------

func (r *AccountIAMReconciler) verifyPrereq(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {
	operatorNames := []string{resources.RedisOperator, resources.IMPackage}

	// Request IM operator and wait for their status
	if err := r.createOperandRequest(ctx, instance, resources.UserMgmtOpreq, operatorNames); err != nil {
		return err
	}

	if err := r.createOperandRBAC(ctx, instance); err != nil {
		return err
	}

	if err := utils.WaitForOperatorReady(ctx, r.Client, resources.UserMgmtOpreq, instance.Namespace); err != nil {
		klog.Errorf("Failed to wait for all operator ready in OperandRequest %s", resources.UserMgmtOpreq)
		return err
	}

	// Create Redis CR and wait for it to be ready
	if err := r.createRedisCR(ctx, instance); err != nil {
		klog.Errorf("Failed to create Redis CR: %v", err)
		return err
	}

	if err := utils.WaitForOperandReady(ctx, r.Client, resources.UserMgmtOpreq, instance.Namespace); err != nil {
		klog.Infof("Failed to wait for all operand ready in OperandRequest %s", resources.UserMgmtOpreq)
		return err
	}

	// Generate PG password
	klog.Info("Generating PG password")
	pgPassword, err := utils.RandStrings(20)
	if err != nil {
		return err
	}

	// Get cp-console route
	klog.Info("Getting cp-console route")
	host, err := utils.GetHost(ctx, r.Client, "cp-console", instance.Namespace)
	if err != nil {
		return err
	}

	// Create bootstrap secret
	klog.Info("Creating bootstrap secret")
	bootstrapsecret, err := r.initBootstrapData(ctx, instance.Namespace, pgPassword[0])
	if err != nil {
		return err
	}

	// Read the values from bootstrap secret and store in BootstrapData struct
	bootstrapConverter, err := yaml.Marshal(bootstrapsecret.Data)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(bootstrapConverter, &BootstrapData); err != nil {
		return err
	}

	// Initialize the MCSPData struct
	if err := r.initMCSPData(ctx, instance.Namespace, host); err != nil {
		return err
	}

	jobs := []string{resources.CreateDBJob, resources.DBMigrationJob, resources.IMConfigJob}
	if err := r.cleanJob(ctx, jobs, instance.Namespace); err != nil {
		klog.Errorf("Failed to clean up jobs: %v", err)
		return err
	}

	return nil
}

// CreateOperandRequest creates an OperandRequest resource
func (r *AccountIAMReconciler) createOperandRequest(ctx context.Context, instance *operatorv1alpha1.AccountIAM, name string, operandNames []string) error {
	operandRequest := &odlm.OperandRequest{}
	if err := r.Get(ctx, client.ObjectKey{Name: name, Namespace: instance.Namespace}, operandRequest); err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		var operands []odlm.Operand
		for _, name := range operandNames {
			operands = append(operands, odlm.Operand{Name: name})
		}

		klog.Infof("Creating OperandRequest %s in namespace %s", name, instance.Namespace)

		operandRequest = &odlm.OperandRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: instance.Namespace,
			},
			Spec: odlm.OperandRequestSpec{
				Requests: []odlm.Request{
					{
						Operands: operands,
						Registry: "common-service",
					},
				},
			},
		}

		if err := controllerutil.SetControllerReference(instance, operandRequest, r.Scheme); err != nil {
			return err
		}

		if err := r.Create(ctx, operandRequest); err != nil {
			if !k8serrors.IsAlreadyExists(err) {
				return err
			}
		}

		klog.Infof("Successfully created OperandRequest %s in namespace %s", name, instance.Namespace)
	} else {
		// OperandRequest already exists; check and set owner reference if needed
		needsUpdate := false

		// Check if the owner reference is missing or incorrect
		if !metav1.IsControlledBy(operandRequest, instance) {
			klog.V(2).Infof("Setting controller reference for OperandRequest %s", operandRequest.Name)
			if err := controllerutil.SetControllerReference(instance, operandRequest, r.Scheme); err != nil {
				return err
			}
			needsUpdate = true
		}

		if needsUpdate {
			if err := r.Update(ctx, operandRequest); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *AccountIAMReconciler) createRedisCR(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {

	// Check if Redis CRD exists
	existRedis, err := utils.CheckCRD(r.Config, utils.Concat(resources.RedisAPIGroup, "/", resources.RedisVersion), resources.RedisKind)
	if err != nil {
		return err
	}
	if !existRedis {
		return errors.New("Redis CRD not found")
	}

	klog.Infof("Creating Redis certificate")
	for _, v := range res.REDIS_CERTS {
		object := &unstructured.Unstructured{}
		manifest := []byte(v)
		if err := yaml.Unmarshal(manifest, object); err != nil {
			return err
		}
		object.SetNamespace(instance.Namespace)
		if err := controllerutil.SetControllerReference(instance, object, r.Scheme); err != nil {
			return err
		}
		if err := r.createOrUpdate(ctx, object); err != nil {
			return err
		}
	}

	// Create Redis CR
	klog.Infof("Redis CRD exists, creating Redis CR %s in namespace %s", resources.Rediscp, instance.Namespace)
	redisCRData := RedisCRParams{
		RedisCRSize:    3,
		RedisCRVersion: "1.2.0",
	}

	if err := r.injectData(ctx, instance, []string{res.RedisCRTemplate}, redisCRData); err != nil {
		klog.Errorf("Failed to create Redis CR: %v", err)
		return err
	}

	// Wait for Redis CR to be ready
	if err := utils.WaitForRediscp(ctx, r.Client, instance.Namespace, resources.Rediscp, resources.RedisAPIGroup, resources.RedisKind, resources.RedisVersion, resources.OperandStatusComp); err != nil {
		return err
	}
	return nil
}

// InitBootstrapData initializes BootstrapData with default values
func (r *AccountIAMReconciler) initBootstrapData(ctx context.Context, ns string, pg []byte) (*corev1.Secret, error) {

	bootstrapsecret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "user-mgmt-bootstrap", Namespace: ns}, bootstrapsecret); err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, err
		}

		clientVars, err := utils.RandStrings(8, 8)
		if err != nil {
			return nil, err
		}
		clinetID := clientVars[0]
		clientSecret := clientVars[1]

		klog.Info("Creating bootstrap secret with PG password")
		newsecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "user-mgmt-bootstrap",
				Namespace: ns,
			},
			Data: map[string][]byte{
				"Realm":               []byte("PrimaryRealm"),
				"ClientID":            clinetID,
				"ClientSecret":        clientSecret,
				"UserValidationAPIV2": []byte("https://openshift.default.svc/apis/user.openshift.io/v1/users/~"),
				"DefaultAUDValue":     clinetID,
				"DefaultRealmValue":   []byte("PrimaryRealm"),
				"SREMCSPGroupsToken":  []byte("mcsp-im-integration-admin"),
				"GlobalRealmValue":    []byte("PrimaryRealm"),
				"GlobalAccountAud":    clinetID,
				"PGPassword":          pg,
			},
			Type: corev1.SecretTypeOpaque,
		}

		if err := r.Create(ctx, newsecret); err != nil {
			if !k8serrors.IsAlreadyExists(err) {
				return nil, err
			}
		}
		return newsecret, nil
	}
	return bootstrapsecret, nil
}

// InitMCSPData initializes MCSPData with default values
func (r *AccountIAMReconciler) initMCSPData(ctx context.Context, ns string, host string) error {
	klog.Infof("Initializing MCSP Data")
	accountIAMHost := strings.Replace(host, "cp-console", "account-iam", 1)
	accountIAMUIHost := strings.Replace(host, "cp-console", "account-iam-console", 1)

	IntegrationData = IntegrationConfig{
		DiscoveryEndpoint:    utils.Concat("https://", host, "/idprovider/v1/auth/.well-known/openid-configuration"),
		DefaultIDPValue:      utils.Concat("https://", host, "/idprovider/v1/auth"),
		GlobalAccountIDP:     utils.Concat("https://", host, "/idprovider/v1/auth"),
		AccountIAMNamespace:  ns,
		IMURL:                utils.Concat("https://", host),
		AccountIAMURL:        utils.Concat("https://", accountIAMHost),
		AccountIAMConsoleURL: utils.Concat("https://", accountIAMUIHost),
	}
	return nil
}

func (r *AccountIAMReconciler) cleanJob(ctx context.Context, jobs []string, ns string) error {

	for _, jobName := range jobs {
		job := &batchv1.Job{}
		namespacedName := types.NamespacedName{Name: jobName, Namespace: ns}

		if err := r.Get(ctx, namespacedName, job); err != nil {
			if k8serrors.IsNotFound(err) {
				klog.Infof("Job %s not found, skipping deletion.", jobName)
				continue
			}
			return err
		}

		// Check if the job is completed successfully
		jobCompleted := false
		for _, condition := range job.Status.Conditions {
			if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
				klog.V(2).Infof("Job %s completed successfully, skipping deletion.", jobName)
				jobCompleted = true
				break
			}
		}

		if jobCompleted {
			continue
		}

		klog.Infof("Deleting incomplete job %s", jobName)
		background := metav1.DeletePropagationBackground
		if err := r.Delete(ctx, job, &client.DeleteOptions{
			PropagationPolicy: &background,
		}); err != nil {
			if !k8serrors.IsNotFound(err) {
				return err
			}
		}
	}

	return nil
}

// if rbac not exist, create RBAC for user-mgmt operand
// if rbac exist, update RBAC for user-mgmt operand
func (r *AccountIAMReconciler) createOperandRBAC(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {
	klog.Infof("Creating or updating RBAC for user-mgmt operand")

	for _, v := range res.OperandRBACs {
		object := &unstructured.Unstructured{}
		manifest := []byte(v)
		if err := yaml.Unmarshal(manifest, object); err != nil {
			return err
		}
		object.SetNamespace(instance.Namespace)
		if err := controllerutil.SetControllerReference(instance, object, r.Scheme); err != nil {
			return err
		}
		if err := r.createOrUpdate(ctx, object); err != nil {
			return err
		}
	}

	return nil
}

// -------------- verifyPrereq helper functions done --------------

// -------------- Reconcile resources helper functions --------------

func (r *AccountIAMReconciler) reconcileOperandResources(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {

	// TODO: will need to find a better place to initialize the database
	klog.Infof("Applying DB Bootstrap Job")
	object := &unstructured.Unstructured{}
	resource := utils.ReplaceImages(res.DB_BOOTSTRAP_JOB)
	manifest := []byte(resource)
	if err := yaml.Unmarshal(manifest, object); err != nil {
		return err
	}
	object.SetNamespace(instance.Namespace)
	if err := controllerutil.SetControllerReference(instance, object, r.Scheme); err != nil {
		return err
	}
	if err := r.createOrUpdate(ctx, object); err != nil {
		return err
	}

	// Manifests which need data injected before creation
	klog.Infof("Creating MCSP secrets")
	// Get WLP client ID
	wlpClientID, err := utils.GetSecretData(ctx, r.Client, resources.IMOIDCCrendential, instance.Namespace, resources.WLPClientID)
	if err != nil {
		klog.Errorf("Failed to get WLP client ID from secret %s in namespace %s", resources.IMOIDCCrendential, instance.Namespace)
		return err
	}
	decodedGlobalAud, err := base64.StdEncoding.DecodeString(BootstrapData.GlobalAccountAud)
	if err != nil {
		return err
	}
	decodedDefaultAud, err := base64.StdEncoding.DecodeString(BootstrapData.DefaultAUDValue)
	if err != nil {
		return err
	}

	BootstrapData.GlobalAccountAud = base64.StdEncoding.EncodeToString([]byte(string(decodedGlobalAud) + "," + wlpClientID))
	BootstrapData.DefaultAUDValue = base64.StdEncoding.EncodeToString([]byte(string(decodedDefaultAud) + "," + wlpClientID))

	if err := r.injectData(ctx, instance, res.APP_SECRETS, BootstrapData, IntegrationData); err != nil {
		return err
	}

	// static manifests which do not change
	klog.Infof("Creating MCSP static yamls")
	for _, v := range res.APP_STATIC_YAMLS {
		object := &unstructured.Unstructured{}
		v = utils.ReplaceImages(v)
		manifest := []byte(v)
		if err := yaml.Unmarshal(manifest, object); err != nil {
			return err
		}
		object.SetNamespace(instance.Namespace)
		if err := controllerutil.SetControllerReference(instance, object, r.Scheme); err != nil {
			return err
		}
		if err := r.createOrUpdate(ctx, object); err != nil {
			return err
		}
	}

	klog.Infof("Creating Account IAM yamls")
	for _, v := range res.ACCOUNT_IAM_RES {
		object := &unstructured.Unstructured{}
		v = utils.ReplaceImages(v)
		manifest := []byte(v)
		if err := yaml.Unmarshal(manifest, object); err != nil {
			return err
		}
		object.SetNamespace(instance.Namespace)
		if err := controllerutil.SetControllerReference(instance, object, r.Scheme); err != nil {
			return err
		}
		if err := r.createOrUpdate(ctx, object); err != nil {
			return err
		}
	}

	klog.Infof("Creating Account IAM Routes")
	caCRT, err := utils.GetSecretData(ctx, r.Client, resources.AccountIAMCACert, instance.Namespace, resources.CAKey)
	if err != nil {
		klog.Errorf("Failed to get ca.crt from secret %s in namespace %s", resources.CSCASecret, instance.Namespace)
		return err
	}

	RouteData := RouteParams{
		CAcert: utils.IndentCert(caCRT, 6),
	}

	if err := r.injectData(ctx, instance, res.ACCOUNT_IAM_ROUTE_RES, RouteData); err != nil {
		return err
	}

	// Update issuer in platform-auth-idp configmap
	klog.Infof("Updating platform-auth-idp configmap")
	idpconfig := &corev1.ConfigMap{}
	if err := r.Get(ctx, client.ObjectKey{Name: resources.IMPlatformCM, Namespace: instance.Namespace}, idpconfig); err != nil {
		klog.Errorf("Failed to get configmap %s in namespace %s: %v", resources.IMPlatformCM, instance.Namespace, err)
		return err
	}

	if idpconfig.Data["OIDC_ISSUER_URL"] == IntegrationData.DefaultIDPValue {
		klog.Infof("ConfigMap platform-auth-idp already has the desired value for OIDC_ISSUER_URL: %s", idpconfig.Data["OIDC_ISSUER_URL"])
		return nil // Skip the update as the value is already set
	}

	idpconfig.Data["OIDC_ISSUER_URL"] = IntegrationData.DefaultIDPValue
	if err := r.Update(ctx, idpconfig); err != nil {
		klog.Errorf("Failed to update ConfigMap platform-auth-idp in namespace %s: %v", instance.Namespace, err)
		return err
	}

	// Delete the platform-auth-service and platform-identity-provider pod to restart it
	if err := r.restartAndCheckPod(ctx, instance.Namespace, "platform-auth-service"); err != nil {
		return err
	}

	if err := r.restartAndCheckPod(ctx, instance.Namespace, "platform-identity-provider"); err != nil {
		return err
	}

	klog.Infof("MCSP operand resources created successfully")
	return nil
}

func (r *AccountIAMReconciler) injectData(ctx context.Context, instance *operatorv1alpha1.AccountIAM, manifests []string, dataList ...interface{}) error {

	// Combine the data from all structs into a single map
	combinedData := utils.CombineData(dataList...)

	var buffer bytes.Buffer
	// Loop through each secret manifest that requires data injection
	for _, manifest := range manifests {
		object := &unstructured.Unstructured{}
		buffer.Reset()

		// Parse the manifest template and execute it with the provided data
		manifest = utils.ReplaceImages(manifest)
		t := template.Must(template.New("template resources").Parse(manifest))
		if err := t.Execute(&buffer, combinedData); err != nil {
			return err
		}

		if err := yaml.Unmarshal(buffer.Bytes(), object); err != nil {
			return err
		}

		object.SetNamespace(instance.Namespace)
		if err := controllerutil.SetControllerReference(instance, object, r.Scheme); err != nil {
			return err
		}

		if err := r.createOrUpdate(ctx, object); err != nil {
			return err
		}
	}

	return nil
}

func (r *AccountIAMReconciler) restartAndCheckPod(ctx context.Context, ns, label string) error {

	// restart platform-auth-service pod and wait for it to be ready
	pod, err := r.getPodName(ctx, ns, label)
	if err != nil {
		return err
	}

	podName := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod,
			Namespace: ns,
		},
	}
	if err := r.Delete(ctx, podName); err != nil {
		klog.Errorf("Failed to delete pod %s in namespace %s", label, ns)
		return err
	}

	time.Sleep(10 * time.Second)

	if err := utils.WaitForDeploymentReady(ctx, r.Client, ns, label); err != nil {
		klog.Error("Failed to wait for Deployment %s to be ready in namespace %s", label, ns)
		return err
	}

	return nil
}

func (r *AccountIAMReconciler) getPodName(ctx context.Context, namespace, label string) (string, error) {
	podList := &corev1.PodList{}
	labelSelector := labels.SelectorFromSet(labels.Set{"app": label})

	if err := r.Client.List(ctx, podList, &client.ListOptions{
		Namespace:     namespace,
		LabelSelector: labelSelector,
	}); err != nil {
		return "", err
	}

	if len(podList.Items) == 0 {
		return "", fmt.Errorf("No pod found with label %s in namespace %s", labelSelector, namespace)
	}
	return podList.Items[0].Name, nil
}

// -------------- Reconcile resources helper functions done --------------

// -------------- Config IM functions --------------

func (r *AccountIAMReconciler) configIM(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {

	klog.Infof("Applying IM Config Job")

	if err := r.injectData(ctx, instance, res.IMConfigYamls, IntegrationData); err != nil {
		return err
	}

	if err := utils.WaitForJob(ctx, r.Client, instance.Namespace, resources.IMConfigJob); err != nil {
		klog.Error("Failed to wait for IM Config Job to be succeeded")
		return err
	}

	return nil
}

// -------------- Config IM functions done --------------

// -------------- Reconcile UI functions --------------

func (r *AccountIAMReconciler) reconcileUI(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {
	if err := r.initUIBootstrapData(ctx, instance); err != nil {
		return err
	}

	// Manifests which need data injected before creation
	object := &unstructured.Unstructured{}
	tmpl := template.New("template for injecting data into YAMLs")
	var tmplWriter bytes.Buffer
	for _, v := range res.TemplateYamlsUI {
		manifest := v
		tmplWriter.Reset()

		tmpl, err := tmpl.Parse(manifest)
		if err != nil {
			return err
		}
		if err := tmpl.Execute(&tmplWriter, UIBootstrapData); err != nil {
			return err
		}

		if err := yaml.Unmarshal(tmplWriter.Bytes(), object); err != nil {
			return err
		}
		object.SetNamespace(instance.Namespace)
		if err := controllerutil.SetControllerReference(instance, object, r.Scheme); err != nil {
			return err
		}
		if err := r.createOrUpdate(ctx, object); err != nil {
			return err
		}
	}

	klog.Infof("Creating static yamls for UI")
	for _, v := range res.StaticYamlsUI {
		object := &unstructured.Unstructured{}
		v = utils.ReplaceImages(v)
		manifest := []byte(v)
		if err := yaml.Unmarshal(manifest, object); err != nil {
			return err
		}
		object.SetNamespace(instance.Namespace)
		if err := controllerutil.SetControllerReference(instance, object, r.Scheme); err != nil {
			return err
		}
		if err := r.createOrUpdate(ctx, object); err != nil {
			return err
		}
	}

	return nil
}

func (r *AccountIAMReconciler) initUIBootstrapData(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {
	klog.Infof("Initializing UI Bootstrap Data")
	clusterInfo := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: instance.Namespace, Name: "ibmcloud-cluster-info"}, clusterInfo); err != nil {
		return err
	}
	if _, ok := clusterInfo.Data["cluster_kube_apiserver_host"]; !ok {
		return errors.New("configmap ibmcloud-cluster-info missing field 'cluster_kube_apiserver_host'")
	}
	cpconsole, ok := clusterInfo.Data["cluster_endpoint"]
	if !ok {
		return errors.New("configmap ibmcloud-cluster-info missing field 'cluster_endpoint'")
	}
	parsing := strings.Split(clusterInfo.Data["cluster_kube_apiserver_host"], ".")
	domain := strings.Join(parsing[1:], ".")
	klog.Infof("domain: %s", domain)

	// Get the API key
	apiKey, err := utils.GetSecretData(ctx, r.Client, resources.IMAPISecret, instance.Namespace, resources.IMAPIKey)
	if err != nil {
		klog.Errorf("Failed to get secret %s in namespace %s: %v", resources.IMAPISecret, instance.Namespace, err)
		return err
	}

	// Get the Redis URL SSL
	redisURlssl, err := utils.GetSecretData(ctx, r.Client, resources.Rediscp, instance.Namespace, resources.RedisURLssl)
	if err != nil {
		klog.Errorf("Failed to get secret %s in namespace %s: %v", resources.Rediscp, instance.Namespace, err)
		return err
	}
	redisURlssl = utils.InsertColonInURL(redisURlssl)

	// get Redis Certificate Authority
	caCRT, err := utils.GetSecretData(ctx, r.Client, resources.RedisCACert, instance.Namespace, resources.CAKey)
	if err != nil {
		klog.Errorf("Failed to get ca.crt from secret %s in namespace %s", resources.CSCASecret, instance.Namespace)
		return err
	}
	caCRT = base64.StdEncoding.EncodeToString([]byte(caCRT))

	SessionSecret, err := utils.RandStrings(48)
	if err != nil {
		return err
	}

	decodedClientID, err := base64.StdEncoding.DecodeString(BootstrapData.ClientID)
	if err != nil {
		return err
	}
	decodedClientSecret, err := base64.StdEncoding.DecodeString(BootstrapData.ClientSecret)
	if err != nil {
		return err
	}

	UIBootstrapData = UIBootstrapTemplate{
		Hostname:                   utils.Concat("account-iam-console-", instance.Namespace, ".apps.", domain),
		InstanceManagementHostname: utils.Concat("account-iam-console-", instance.Namespace, ".apps.", domain),
		ClientID:                   string(decodedClientID),
		ClientSecret:               string(decodedClientSecret),
		IAMGlobalAPIKey:            string(apiKey),
		RedisHost:                  redisURlssl,
		RedisCA:                    caCRT,
		SessionSecret:              string(SessionSecret[0]),
		DeploymentCloud:            "IBM_CLOUD",
		IAMAPI:                     utils.Concat("https://account-iam-", instance.Namespace, ".apps.", domain),
		NodeEnv:                    "production",
		CertDir:                    "../../security",
		ConfigEnv:                  "dev",
		IssuerBaseURL:              utils.Concat(cpconsole, "/idprovider/v1/auth"),
		IMIDMgmt:                   cpconsole,
		CSIDPURL:                   utils.Concat(cpconsole, "/common-nav/identity-access/realms"),
		DefaultAccount:             "default-account",
		DefaultInstance:            "default-service",
	}

	return nil
}

// -------------- Reconcile UI functions done --------------

func (r *AccountIAMReconciler) createOrUpdate(ctx context.Context, obj *unstructured.Unstructured) error {

	fromCluster := &unstructured.Unstructured{}
	fromCluster.SetGroupVersionKind(obj.GroupVersionKind())
	err := r.Get(ctx, types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}, fromCluster)

	if err != nil {
		if k8serrors.IsNotFound(err) {
			_, templateHash, err := utils.CalculateHashes(nil, obj)
			if err != nil {
				return err
			}
			utils.SetHashAnnotation(obj, templateHash)

			if err := r.Create(ctx, obj); err != nil {
				return err
			}
			klog.V(2).Infof("Created resource %s %s/%s.", obj.GetKind(), obj.GetNamespace(), obj.GetName())
			return nil
		}
		return err
	}

	if skipUpdate, ok := fromCluster.GetAnnotations()[resources.SkipAnnotation]; ok && skipUpdate == "true" {
		klog.Infof("Skipping update for %s %s/%s.", obj.GetKind(), obj.GetNamespace(), obj.GetName())
		return nil
	}

	// Get the hash of the existing and new resources
	clusterHash, templateHash, err := utils.CalculateHashes(fromCluster, obj)
	if err != nil {
		return err
	}

	if obj.GetKind() == "Job" {
		if templateHash == clusterHash {
			klog.V(2).Infof("Job resource %s %s/%s has not changed, skipping update.", obj.GetKind(), obj.GetNamespace(), obj.GetName())
			return nil
		}

		if err := r.Delete(ctx, fromCluster); err != nil {
			return err
		}

		time.Sleep(10 * time.Second)

		utils.SetHashAnnotation(obj, templateHash)

		if err := r.Create(ctx, obj); err != nil {
			return err
		}
		klog.Infof("Recreated Job resource %s %s/%s due to hash mismatch.", obj.GetKind(), obj.GetNamespace(), obj.GetName())
		return nil
	}

	// handle non-Job resources
	if clusterHash == templateHash {
		// Merge fromTemplate into fromCluster and update

		mergedObj, err := utils.MergeResources(fromCluster, obj)
		if err != nil {
			return err
		}

		utils.SetHashAnnotation(mergedObj, templateHash)
		mergedObj.SetResourceVersion(fromCluster.GetResourceVersion())

		if err := r.Update(ctx, mergedObj); err != nil {
			return err
		}
		klog.V(2).Infof("Updated resource %s %s/%s with merged fields.", obj.GetKind(), obj.GetNamespace(), obj.GetName())
		return nil
	}

	// If hashes don't match, overwrite fromCluster with fromTemplate
	utils.SetHashAnnotation(obj, templateHash)

	// Update the resource if the configuration has changed
	obj.SetResourceVersion(fromCluster.GetResourceVersion())
	if err := r.Update(ctx, obj); err != nil {
		return err
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AccountIAMReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&operatorv1alpha1.AccountIAM{}).
		//Owns(&appsv1.Deployment{}).
		//Owns(&corev1.Secret{}).
		//Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		//Owns(&corev1.ServiceAccount{}).
		Owns(&routev1.Route{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Owns(&batchv1.Job{}).
		Owns(&certmgrv1.Certificate{}).
		Owns(&certmgrv1.Issuer{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Complete(r)
}
