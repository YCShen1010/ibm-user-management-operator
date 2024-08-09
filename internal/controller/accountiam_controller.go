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
	"os"
	"reflect"
	"strings"
	"text/template"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
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
	"github.com/IBM/ibm-user-management-operator/internal/resources"
	res "github.com/IBM/ibm-user-management-operator/internal/resources/yamls"
	odlm "github.com/IBM/operand-deployment-lifecycle-manager/v4/api/v1alpha1"
	"github.com/ghodss/yaml"
	olmapi "github.com/operator-framework/api/pkg/operators/v1"
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
	DiscoveryEndpoint   string
	PGPassword          string
	DefaultAUDValue     string
	DefaultIDPValue     string
	DefaultRealmValue   string
	SREMCSPGroupsToken  string
	GlobalRealmValue    string
	GlobalAccountIDP    string
	GlobalAccountAud    string
	UserValidationAPIV2 string
	IAMHostURL          string
	AccountIAMURL       string
	AccountIAMHostURL   string
	AccountIAMNamespace string
}

var BootstrapData BootstrapSecret

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
	OnPremAccount               string
	OnPremInstance              string
}

var UIBootstrapData UIBootstrapTemplate

//+kubebuilder:rbac:groups=operator.ibm.com,resources=accountiams,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.ibm.com,resources=accountiams/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=operator.ibm.com,resources=accountiams/finalizers,verbs=update
//+kubebuilder:rbac:groups=operator.ibm.com,resources=operandrequests,verbs=get;list;watch;create
//+kubebuilder:rbac:groups=operators.coreos.com,resources=operatorgroups,verbs=get;list;watch
//+kubebuilder:rbac:groups=redis.ibm.com,resources=rediscps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes/custom-host,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=liberty.websphere.ibm.com,resources=webspherelibertyapplications,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings;roles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.openshift.io,resources=securitycontextconstraints,verbs=use
//+kubebuilder:rbac:groups=cert-manager.io,resources=issuers;certificates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

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

	return ctrl.Result{}, nil
}

// -------------- verifyPrereq helper functions --------------

func (r *AccountIAMReconciler) verifyPrereq(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {
	og := &olmapi.OperatorGroupList{}
	err := r.Client.List(ctx, og, &client.ListOptions{
		Namespace: os.Getenv("WATCH_NAMESPACE"),
	})
	if err != nil {
		return err
	}

	operatorNames := []string{resources.WebSpherePackage, resources.RedisOperator, resources.IMPackage}

	// Request WebSphere, IM operator and wait for their status
	if err := r.createOperandRequest(ctx, instance, resources.UserMgmtOpreq, operatorNames); err != nil {
		return err
	}

	if err := waitForOperatorReady(ctx, r.Client, resources.UserMgmtOpreq, instance.Namespace); err != nil {
		klog.Errorf("Failed to wait for all operator ready in OperandRequest %s", resources.UserMgmtOpreq)
		return err
	}

	// Create Redis CR and wait for it to be ready
	if err := r.createRedisCR(ctx, instance); err != nil {
		klog.Errorf("Failed to create Redis CR: %v", err)
		return err
	}

	if err := waitForOperandReady(ctx, r.Client, resources.UserMgmtOpreq, instance.Namespace); err != nil {
		klog.Infof("Failed to wait for all operand ready in OperandRequest %s", resources.UserMgmtOpreq)
		return err
	}

	existWebsphere, err := CheckCRD(r.Config, resources.WebSphereAPIGroupVersion, resources.WebSphereKind)
	if err != nil {
		return err
	}
	if !existWebsphere {
		return errors.New("Missing WebSphereLibertyApplication CRD")
	}

	// Generate PG password
	klog.Info("Generating PG password")
	pgPassword, err := generatePassword(20)

	if err != nil {
		return err
	}

	// Get cp-console route
	klog.Info("Getting cp-console route")
	host, err := getHost(ctx, r.Client, "cp-console", instance.Namespace)
	if err != nil {
		return err
	}

	// Create bootstrap secret
	klog.Info("Creating bootstrap secret")
	bootstrapsecret, err := r.initBootstrapData(ctx, instance.Namespace, pgPassword, host)
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

		operandReq := &odlm.OperandRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				// Labels: map[string]string{
				// 	"app.kubernetes.io/instance":   "operand-deployment-lifecycle-manager",
				// 	"app.kubernetes.io/managed-by": "operand-deployment-lifecycle-manager",
				// 	"app.kubernetes.io/name":       "operand-deployment-lifecycle-manager",
				// },
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

		operandReq.SetNamespace(instance.Namespace)
		if err := controllerutil.SetControllerReference(instance, operandReq, r.Scheme); err != nil {
			return err
		}

		if err := r.Create(ctx, operandReq); err != nil {
			if !k8serrors.IsAlreadyExists(err) {
				return err
			}
		}
	}

	klog.Infof("Successfully created OperandRequest %s in namespace %s", name, instance.Namespace)
	return nil
}

func (r *AccountIAMReconciler) createRedisCR(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {

	// Check if Redis CRD exists
	existRedis, err := CheckCRD(r.Config, concat(resources.RedisAPIGroup, "/", resources.RedisVersion), resources.RedisKind)
	if err != nil {
		return err
	}
	if !existRedis {
		return errors.New("Redis CRD not found")
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
	if err := waitForRediscp(ctx, r.Client, instance.Namespace, resources.Rediscp, resources.RedisAPIGroup, resources.RedisKind, resources.RedisVersion, resources.OperandStatusComp); err != nil {
		return err
	}
	return nil
}

// InitBootstrapData initializes BootstrapData with default values
func (r *AccountIAMReconciler) initBootstrapData(ctx context.Context, ns string, pg []byte, host string) (*corev1.Secret, error) {

	bootstrapsecret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "user-mgmt-bootstrap", Namespace: ns}, bootstrapsecret); err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, err
		}

		accountIAMHost := strings.Replace(host, "cp-console", "account-iam-console", 1)
		klog.Info("Creating bootstrap secret with PG password")
		newsecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "user-mgmt-bootstrap",
				Namespace: ns,
			},
			Data: map[string][]byte{
				"Realm":               []byte("PrimaryRealm"),
				"ClientID":            []byte("mcsp-id"),
				"ClientSecret":        []byte("mcsp-secret"),
				"DiscoveryEndpoint":   []byte("https://" + host + "/idprovider/v1/auth/.well-known/openid-configuration"),
				"UserValidationAPIV2": []byte("https://openshift.default.svc/apis/user.openshift.io/v1/users/~"),
				"DefaultAUDValue":     []byte("mcsp-id"),
				"DefaultIDPValue":     []byte("https://" + host + "/idprovider/v1/auth"),
				"DefaultRealmValue":   []byte("PrimaryRealm"),
				"SREMCSPGroupsToken":  []byte("mcsp-im-integration-admin"),
				"GlobalRealmValue":    []byte("PrimaryRealm"),
				"GlobalAccountIDP":    []byte("https://" + host + "/idprovider/v1/auth"),
				"GlobalAccountAud":    []byte("mcsp-id"),
				"AccountIAMNamespace": []byte(ns),
				"PGPassword":          pg,
				"IAMHostURL":          []byte("https://" + host),
				"AccountIAMHostURL":   []byte("https://" + accountIAMHost),
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

// -------------- verifyPrereq helper functions done --------------

// -------------- Reconcile resources helper functions --------------

func (r *AccountIAMReconciler) reconcileOperandResources(ctx context.Context, instance *operatorv1alpha1.AccountIAM) error {

	// TODO: will need to find a better place to initialize the database
	klog.Infof("Applying DB Bootstrap Job")
	object := &unstructured.Unstructured{}
	resource := replaceImages(res.DB_BOOTSTRAP_JOB)
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
	if err := r.injectData(ctx, instance, res.APP_SECRETS, BootstrapData); err != nil {
		return err
	}

	klog.Infof("Creating MCSP ConfigMaps")
	decodedData, err := r.decodeData(BootstrapData)
	if err != nil {
		return err
	}

	if err := r.injectData(ctx, instance, res.APP_CONFIGS, decodedData); err != nil {
		return err
	}

	// static manifests which do not change
	klog.Infof("Creating MCSP static yamls")
	staticYamls := append(res.APP_STATIC_YAMLS, res.CertRotationYamls...)
	for _, v := range staticYamls {
		object := &unstructured.Unstructured{}
		v = replaceImages(v)
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

	// Temporary update issuer in platform-auth-idp configmap
	klog.Infof("Updating platform-auth-idp configmap")
	idpconfig := &corev1.ConfigMap{}
	if err := r.Get(ctx, client.ObjectKey{Name: "platform-auth-idp", Namespace: instance.Namespace}, idpconfig); err != nil {
		klog.Errorf("Failed to get configmap platform-auth-idp in namespace %s", instance.Namespace)
		return err
	}
	currentIssuer := idpconfig.Data["OIDC_ISSUER_URL"]
	idpValue := decodedData.DefaultIDPValue

	if currentIssuer == idpValue {
		klog.Infof("ConfigMap platform-auth-idp already has the desired value for OIDC_ISSUER_URL: %s", currentIssuer)
		return nil // Skip the update as the value is already set
	}

	idpconfig.Data["OIDC_ISSUER_URL"] = decodedData.DefaultIDPValue
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

func (r *AccountIAMReconciler) injectData(ctx context.Context, instance *operatorv1alpha1.AccountIAM, manifests []string, data interface{}) error {

	var buffer bytes.Buffer

	// Loop through each secret manifest that requires data injection
	for _, manifest := range manifests {
		object := &unstructured.Unstructured{}
		buffer.Reset()

		// Parse the manifest template and execute it with the provided bootstrap data
		manifest = replaceImages(manifest)
		t := template.Must(template.New("template resrouces").Parse(manifest))
		if err := t.Execute(&buffer, data); err != nil {
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

func (r *AccountIAMReconciler) decodeData(data BootstrapSecret) (BootstrapSecret, error) {
	val := reflect.ValueOf(&data).Elem()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		if field.Kind() == reflect.String {
			decoded, err := base64.StdEncoding.DecodeString(field.String())
			if err != nil {
				return data, err
			}
			field.SetString(string(decoded))
		}
	}
	return data, nil
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

	if err := waitForDeploymentReady(ctx, r.Client, ns, label); err != nil {
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

	host, err := getHost(ctx, r.Client, "account-iam", instance.Namespace)
	if err != nil {
		return err
	}

	mcspHost := "https://" + host
	encodedURL := base64.StdEncoding.EncodeToString([]byte(mcspHost))
	BootstrapData.AccountIAMURL = encodedURL

	klog.Infof("Applying IM Config Job")
	decodedData, err := r.decodeData(BootstrapData)
	if err != nil {
		return err
	}

	if err := r.injectData(ctx, instance, res.IMConfigYamls, decodedData); err != nil {
		return err
	}

	if err := waitForJob(ctx, r.Client, instance.Namespace, resources.IMConfigJob); err != nil {
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

	for _, v := range res.StaticYamlsUI {
		object := &unstructured.Unstructured{}
		v = replaceImages(v)
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
	apiKey, err := getSecretData(ctx, r.Client, resources.IMAPISecret, instance.Namespace, resources.IMAPIKey)
	if err != nil {
		klog.Errorf("Failed to get secret %s in namespace %s: %v", resources.IMAPISecret, instance.Namespace, err)
		return err
	}
	klog.Infof("apiKey: %s", apiKey)

	// Get the Redis URL SSL
	redisURlssl, err := getSecretData(ctx, r.Client, resources.Rediscp, instance.Namespace, resources.RedisURLssl)
	if err != nil {
		klog.Errorf("Failed to get secret %s in namespace %s: %v", resources.Rediscp, instance.Namespace, err)
		return err
	}
	redisURlssl = insertColonInURL(redisURlssl)
	klog.Infof("redisURlssl: %s", redisURlssl)

	// get Redis cert
	redisCert, err := getSecretData(ctx, r.Client, resources.RedisCert, instance.Namespace, resources.RedisCertKey)
	if err != nil {
		klog.Errorf("Failed to get secret %s in namespace %s: %v", resources.RedisCert, instance.Namespace, err)
		return err
	} else {
		klog.Infof("redisCert: %s", redisCert)
	}

	SessionSecret, err := generatePassword(48)
	if err != nil {
		return err
	}
	klog.Info("SessionSecret: ", string(SessionSecret))

	decodedClientID, err := base64.StdEncoding.DecodeString(BootstrapData.ClientID)
	if err != nil {
		return err
	}
	decodedClientSecret, err := base64.StdEncoding.DecodeString(BootstrapData.ClientSecret)
	if err != nil {
		return err
	}

	UIBootstrapData = UIBootstrapTemplate{
		Hostname:                   concat("account-iam-console-", instance.Namespace, ".apps.", domain),
		InstanceManagementHostname: concat("account-iam-console-", instance.Namespace, ".apps.", domain),
		ClientID:                   string(decodedClientID),
		ClientSecret:               string(decodedClientSecret),
		IAMGlobalAPIKey:            string(apiKey),
		RedisHost:                  redisURlssl,
		RedisCA:                    redisCert,
		SessionSecret:              string(SessionSecret),
		DeploymentCloud:            "IBM_CLOUD",
		IAMAPI:                     concat("https://account-iam-", instance.Namespace, ".apps.", domain),
		NodeEnv:                    "production",
		CertDir:                    "../../security",
		ConfigEnv:                  "dev",
		IssuerBaseURL:              concat(cpconsole, "/idprovider/v1/auth"),
		IMIDMgmt:                   cpconsole,
		CSIDPURL:                   concat(cpconsole, "/common-nav/identity-access/realms"),
		OnPremAccount:              "default-account",
		OnPremInstance:             "default-service",
	}

	return nil
}

// -------------- Reconcile UI functions done --------------

func (r *AccountIAMReconciler) createOrUpdate(ctx context.Context, obj *unstructured.Unstructured) error {
	// err := r.Update(ctx, obj)
	// if err != nil {
	// 	if !k8serrors.IsNotFound(err) {
	// 		return err
	// 	}
	// }
	// if err == nil {
	// 	return nil
	// }

	// only reachable if update DID see error IsNotFound
	err := r.Create(ctx, obj)
	if err != nil {
		if !k8serrors.IsAlreadyExists(err) {
			return err
		}
	}

	// if the obj is Job, skip the update
	if obj.GetKind() == "Job" {
		return nil
	}

	fromCluster := &unstructured.Unstructured{}
	fromCluster.SetKind(obj.GetKind())
	fromCluster.SetAPIVersion(obj.GetAPIVersion())
	if err := r.Get(ctx, types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}, fromCluster); err != nil {
		return err
	}
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
		Complete(r)
}
