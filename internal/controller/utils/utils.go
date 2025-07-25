//
// Copyright 2022 IBM Corporation
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

package utils

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/IBM/ibm-user-management-operator/internal/resources"
	odlm "github.com/IBM/operand-deployment-lifecycle-manager/v4/api/v1alpha1"
	routev1 "github.com/openshift/api/route/v1"
	"gopkg.in/yaml.v2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetOperatorNamespace returns the Namespace of the operator
func GetOperatorNamespace() string {
	ns, found := os.LookupEnv("OPERATOR_NAMESPACE")
	if !found {
		return ""
	}
	return ns
}

// GetWatchNamespace returns the Namespace of the operator
func GetWatchNamespace() string {
	ns, found := os.LookupEnv("WATCH_NAMESPACE")
	if !found {
		return GetOperatorNamespace()
	}
	return ns
}

// NewUnstructured return Unstructured object
func NewUnstructured(group, kind, version string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   group,
		Kind:    kind,
		Version: version})
	return u
}

// CheckCRD returns true if the given crd is existent
func CheckCRD(config *rest.Config, apiGroupVersion string, kind string) (bool, error) {
	dc := discovery.NewDiscoveryClientForConfigOrDie(config)
	exist, err := ResourceExists(dc, apiGroupVersion, kind)
	if err != nil {
		return false, err
	}
	if !exist {
		return false, nil
	}
	return true, nil
}

// ResourceExists returns true if the given resource kind exists
// in the given api groupversion
func ResourceExists(dc discovery.DiscoveryInterface, apiGroupVersion, kind string) (bool, error) {
	_, apiLists, err := dc.ServerGroupsAndResources()
	if err != nil {
		return false, err
	}
	for _, apiList := range apiLists {
		if apiList.GroupVersion == apiGroupVersion {
			for _, r := range apiList.APIResources {
				if r.Kind == kind {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// RandStrings generates series of random strings by given lengths
func RandStrings(lengths ...int) ([][]byte, error) {
	results := make([][]byte, len(lengths))

	for i, length := range lengths {
		random := make([]byte, length)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		encoded := base64.StdEncoding.EncodeToString(random)
		encodedFinal := base64.StdEncoding.EncodeToString([]byte(encoded))
		results[i] = []byte(encodedFinal)
	}

	return results, nil
}

// Get the host of the route
func GetHost(ctx context.Context, k8sClient client.Client, name string, ns string) (string, error) {
	sourceRoute := &routev1.Route{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, sourceRoute); err != nil {
		klog.Errorf("Failed to get route %s in namespace %s", name, ns)
		return "", err
	}
	return sourceRoute.Spec.Host, nil
}

func Concat(s ...string) string {
	return strings.Join(s, "")
}

// GetSecretData gets the data from a secret
func GetSecretData(ctx context.Context, k8sClient client.Client, secretName, ns, dataKey string) (string, error) {
	secret := &corev1.Secret{}

	if err := k8sClient.Get(ctx, types.NamespacedName{Name: secretName, Namespace: ns}, secret); err != nil {
		return "", err
	}

	data, ok := secret.Data[dataKey]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", dataKey, secretName)
	}

	return string(data), nil
}

func CombineData(dataStructs ...interface{}) map[string]interface{} {
	combinedData := make(map[string]interface{})

	for _, dataStruct := range dataStructs {
		value := reflect.ValueOf(dataStruct)
		types := reflect.TypeOf(dataStruct)

		if value.Kind() == reflect.Ptr {
			value = value.Elem()
			types = types.Elem()
		}

		if value.Kind() != reflect.Struct {
			continue
		}

		for i := 0; i < value.NumField(); i++ {
			fieldName := types.Field(i).Name
			fieldValue := value.Field(i).Interface()
			combinedData[fieldName] = fieldValue
		}
	}

	return combinedData
}

// indentCertificate to add indentation to each line of the certificate
func IndentCert(cert string, indentSpaces int) string {
	lines := strings.Split(cert, "\n")
	indent := strings.Repeat(" ", indentSpaces)
	for i, line := range lines {
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
}

// GetRedisInfo extracts hostname and port from a Redis URL.
// If the URL does not specify a port, the default port 6379 is used.
func GetRedisInfo(redisURL string) (string, string, error) {
	u, err := url.Parse(redisURL)
	if err != nil {
		return "", "", fmt.Errorf("error parsing redis URL: %w", err)
	}

	hostname := u.Hostname()
	port := u.Port()

	if port == "" {
		port = "6379" // default port for Redis
	}

	return hostname, port, nil
}

// CalculateHashes calculates the hash for the existing cluster resource and the new template resource
func CalculateHashes(fromCluster *unstructured.Unstructured, fromTemplate *unstructured.Unstructured) (string, string, error) {

	templateData, err := yaml.Marshal(fromTemplate.Object)
	if err != nil {
		return "", "", err
	}
	templateHash := sha256.Sum256(templateData)
	templateHashStr := hex.EncodeToString(templateHash[:7])

	if fromCluster != nil {
		clusterAnnos := fromCluster.GetAnnotations()
		clusterHash := ""
		if clusterAnnos != nil {
			clusterHash = clusterAnnos[resources.HashedData]
		}
		return clusterHash, templateHashStr, nil
	}
	return "", templateHashStr, nil
}

// SetHashAnnotation sets the hash annotation in the object
func SetHashAnnotation(obj *unstructured.Unstructured, hash string) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[resources.HashedData] = hash
	obj.SetAnnotations(annotations)
}

// MergeResources merges two complete unstructured Kubernetes resources
func MergeResources(fromCluster, fromTemplate *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	// Marshal both unstructured resources into []byte (JSON format)
	fromClusterBytes, err := json.Marshal(fromCluster.Object)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal fromCluster resource: %v", err)
	}

	fromTemplateBytes, err := json.Marshal(fromTemplate.Object)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal fromTemplate resource: %v", err)
	}

	// Merge the resources
	mergedResource := MergeCR(fromClusterBytes, fromTemplateBytes)

	// Convert mergedResource back to unstructured.Unstructured object
	mergedUnstructured := &unstructured.Unstructured{
		Object: mergedResource,
	}

	return mergedUnstructured, nil
}

// MergeCR deep merges two custom resource specs, along with labels and annotations.
func MergeCR(defaultCR, changedCR []byte) map[string]interface{} {
	if len(defaultCR) == 0 && len(changedCR) == 0 {
		return make(map[string]interface{})
	}

	defaultCRDecoded := make(map[string]interface{})
	changedCRDecoded := make(map[string]interface{})

	// Handle when only one CR is provided
	if len(defaultCR) != 0 && len(changedCR) == 0 {
		if err := json.Unmarshal(defaultCR, &defaultCRDecoded); err != nil {
			klog.Errorf("failed to unmarshal Template CR: %v", err)
		}
		return defaultCRDecoded
	} else if len(defaultCR) == 0 && len(changedCR) != 0 {
		if err := json.Unmarshal(changedCR, &changedCRDecoded); err != nil {
			klog.Errorf("failed to unmarshal existing CR: %v", err)
		}
		return changedCRDecoded
	}

	if err := json.Unmarshal(defaultCR, &defaultCRDecoded); err != nil {
		klog.Errorf("failed to unmarshal Template CR: %v", err)
	}
	if err := json.Unmarshal(changedCR, &changedCRDecoded); err != nil {
		klog.Errorf("failed to unmarshal existing CR: %v", err)
	}

	// Merge both specs
	for key := range defaultCRDecoded {
		checkKeyBeforeMerging(key, defaultCRDecoded[key], changedCRDecoded[key], changedCRDecoded)
	}

	// Ensure labels and annotations are merged as well
	mergeMetadata(defaultCRDecoded, changedCRDecoded)

	return changedCRDecoded
}

// Helper function to merge metadata like labels and annotations
func mergeMetadata(defaultCRDecoded, changedCRDecoded map[string]interface{}) {
	// Handle metadata section
	if defaultMeta, ok := defaultCRDecoded["metadata"].(map[string]interface{}); ok {
		if changedMeta, ok := changedCRDecoded["metadata"].(map[string]interface{}); ok {
			// Merge labels
			if defaultLabels, ok := defaultMeta["labels"].(map[string]interface{}); ok {
				if changedLabels, ok := changedMeta["labels"].(map[string]interface{}); ok {
					for key, value := range defaultLabels {
						changedLabels[key] = value
					}
				} else {
					changedMeta["labels"] = defaultLabels
				}
			}
			if defaultAnnotations, ok := defaultMeta["annotations"].(map[string]interface{}); ok {
				if changedAnnotations, ok := changedMeta["annotations"].(map[string]interface{}); ok {
					for key, value := range defaultAnnotations {
						changedAnnotations[key] = value
					}
				} else {
					changedMeta["annotations"] = defaultAnnotations
				}
			}
		} else {
			changedCRDecoded["metadata"] = defaultMeta
		}
	}
}

// Recursive function to merge spec
func checkKeyBeforeMerging(key string, defaultMap, changedMap interface{}, finalMap map[string]interface{}) {
	if !equality.Semantic.DeepEqual(defaultMap, changedMap) {
		switch defaultVal := defaultMap.(type) {
		case map[string]interface{}:
			if changedMap == nil {
				finalMap[key] = defaultVal
			} else if changedVal, ok := changedMap.(map[string]interface{}); ok {
				for newKey := range defaultVal {
					checkKeyBeforeMerging(newKey, defaultVal[newKey], changedVal[newKey], finalMap[key].(map[string]interface{}))
				}
			}
		case []interface{}:
			if changedMap == nil {
				finalMap[key] = defaultVal
			} else if changedVal, ok := changedMap.([]interface{}); ok {
				for i := range defaultVal {
					if _, ok := defaultVal[i].(map[string]interface{}); ok {
						if len(changedVal) > i {
							for newKey := range defaultVal[i].(map[string]interface{}) {
								checkKeyBeforeMerging(newKey, defaultVal[i].(map[string]interface{})[newKey], changedVal[i].(map[string]interface{})[newKey], finalMap[key].([]interface{})[i].(map[string]interface{}))
							}
						}
					}
				}
			}
		default:
			if changedMap == nil {
				finalMap[key] = defaultVal
			}
		}
	}
}

// ------------------ Resource Status Functions --------------

// GetRedisResourceStatus checks the status of Redis resources
func GetRedisResourceStatus(ctx context.Context, k8sClient client.Client, namespace string) (odlm.ResourceStatus, bool) {
	redisResource := odlm.ResourceStatus{
		ObjectName: resources.Rediscp,
		Namespace:  namespace,
		Kind:       resources.RedisKind,
		APIVersion: resources.RedisAPIGroup + "/" + resources.Version,
		Status:     resources.StatusNotReady,
	}

	redisCR := NewUnstructured(resources.RedisAPIGroup, resources.RedisKind, resources.Version)
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: resources.Rediscp, Namespace: namespace}, redisCR); err != nil {
		if !k8serrors.IsNotFound(err) {
			klog.Error(err, "Failed to get Redis CR")
			redisResource.Status = resources.StatusError
			return redisResource, false
		} else {
			redisResource.Status = resources.StatusNotFound
			return redisResource, false
		}
	}

	status, found, err := unstructured.NestedString(redisCR.Object, "status", resources.RedisStatus)
	if err != nil || !found {
		redisResource.Status = resources.StatusError
		return redisResource, false
	} else if status == resources.StatusCompleted {
		redisResource.Status = resources.StatusCompleted
		return redisResource, true
	} else {
		redisResource.Status = resources.StatusNotReady
		return redisResource, false
	}
}

// GetOperandRequestStatus checks the status of OperandRequest
func GetOperandRequestStatus(ctx context.Context, k8sClient client.Client, namespace string) (odlm.ResourceStatus, bool) {
	umOpreqResource := odlm.ResourceStatus{
		ObjectName: resources.UserMgmtOpreq,
		Namespace:  namespace,
		Kind:       resources.OpreqKind,
		APIVersion: resources.OperatorIBMApiVersion,
		Status:     resources.StatusNotReady,
	}

	operandReq := &odlm.OperandRequest{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: resources.UserMgmtOpreq, Namespace: namespace}, operandReq); err != nil {
		if !k8serrors.IsNotFound(err) {
			klog.Error(err, "Failed to get OperandRequest %s in namespace %s", resources.UserMgmtOpreq, namespace)
			umOpreqResource.Status = resources.StatusError
			return umOpreqResource, false
		} else {
			umOpreqResource.Status = resources.StatusNotFound
			return umOpreqResource, false
		}
	}

	if operandReq.Status.Phase == resources.PhaseRunning {
		umOpreqResource.Status = resources.PhaseRunning
		return umOpreqResource, true
	} else {
		umOpreqResource.Status = string(operandReq.Status.Phase)
		return umOpreqResource, false
	}
}

// GetJobStatus checks the status of a specific job
func GetJobStatus(ctx context.Context, k8sClient client.Client, jobName, namespace string) (odlm.ResourceStatus, bool) {
	jobResource := odlm.ResourceStatus{
		ObjectName: jobName,
		Namespace:  namespace,
		Kind:       resources.JobKind,
		APIVersion: resources.JobAPIGroup,
		Status:     resources.StatusNotReady,
	}

	job := &batchv1.Job{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: jobName, Namespace: namespace}, job); err != nil {
		if !k8serrors.IsNotFound(err) {
			klog.Error(err, "Failed to get Job %s in namespace %s", jobName, namespace)
			jobResource.Status = resources.StatusError
			return jobResource, false
		} else {
			jobResource.Status = resources.StatusNotFound
			return jobResource, false
		}
	}

	for _, condition := range job.Status.Conditions {
		if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
			jobResource.Status = resources.StatusCompleted
			return jobResource, true
		}
		if condition.Type == batchv1.JobFailed && condition.Status == corev1.ConditionTrue {
			jobResource.Status = resources.StatusFailed
			return jobResource, false
		}
	}

	// Job is still running
	jobResource.Status = resources.PhaseRunning
	return jobResource, false
}

// GetServiceStatus checks if a service exists and is properly configured
func GetServiceStatus(ctx context.Context, k8sClient client.Client, serviceName, namespace string) (odlm.ResourceStatus, bool) {
	serviceResource := odlm.ResourceStatus{
		ObjectName: serviceName,
		Namespace:  namespace,
		Kind:       resources.ServiceKind,
		APIVersion: resources.Version,
		Status:     resources.StatusNotReady,
	}

	service := &corev1.Service{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: serviceName, Namespace: namespace}, service); err != nil {
		if !k8serrors.IsNotFound(err) {
			klog.Error(err, "Failed to get Service %s in namespace %s", serviceName, namespace)
			serviceResource.Status = resources.StatusError
			return serviceResource, false
		} else {
			serviceResource.Status = resources.StatusNotFound
			return serviceResource, false
		}
	}

	// Check if the service has cluster IP assigned
	if service.Spec.ClusterIP == "" || service.Spec.ClusterIP == "None" {
		// This is a headless service which is OK
		if service.Spec.Type == "ClusterIP" && service.Spec.ClusterIP == "None" {
			serviceResource.Status = resources.StatusCompleted
			return serviceResource, true
		}

		serviceResource.Status = resources.StatusNotReady
		return serviceResource, false
	}

	// Service exists with ClusterIP, consider it ready
	serviceResource.Status = resources.StatusCompleted
	return serviceResource, true
}

// GetSecretStatus checks if a secret exists and is properly configured
func GetSecretStatus(ctx context.Context, k8sClient client.Client, secretName, namespace string) (odlm.ResourceStatus, bool) {
	secretResource := odlm.ResourceStatus{
		ObjectName: secretName,
		Namespace:  namespace,
		Kind:       resources.SecretKind,
		APIVersion: resources.Version,
		Status:     resources.StatusNotReady,
	}

	secret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: secretName, Namespace: namespace}, secret); err != nil {
		if !k8serrors.IsNotFound(err) {
			klog.Error(err, "Failed to get Secret %s in namespace %s", secretName, namespace)
			secretResource.Status = resources.StatusError
			return secretResource, false
		} else {
			secretResource.Status = resources.StatusNotFound
			return secretResource, false
		}
	}

	// Secret exists, consider it ready
	secretResource.Status = resources.StatusCompleted
	return secretResource, true
}

// GetRouteStatus checks if a route exists and is properly configured
func GetRouteStatus(ctx context.Context, k8sClient client.Client, routeName, namespace string) (odlm.ResourceStatus, bool) {
	routeResource := odlm.ResourceStatus{
		ObjectName: routeName,
		Namespace:  namespace,
		Kind:       resources.RouteKind,
		APIVersion: resources.RouteAPIGroup + "/" + resources.Version,
		Status:     resources.StatusNotReady,
	}

	route := &routev1.Route{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: routeName, Namespace: namespace}, route); err != nil {
		if !k8serrors.IsNotFound(err) {
			klog.Error(err, "Failed to get Route %s in namespace %s", routeName, namespace)
			routeResource.Status = resources.StatusError
			return routeResource, false
		} else {
			routeResource.Status = resources.StatusNotFound
			return routeResource, false
		}
	}

	// Check if the route has ingress
	if len(route.Status.Ingress) == 0 {
		routeResource.Status = resources.StatusNotReady
		return routeResource, false
	}

	// Check if at least one ingress is admitted
	for _, ingress := range route.Status.Ingress {
		for _, condition := range ingress.Conditions {
			if condition.Type == routev1.RouteAdmitted && condition.Status == corev1.ConditionTrue {
				routeResource.Status = resources.StatusCompleted
				return routeResource, true
			}
		}
	}

	routeResource.Status = resources.StatusNotReady
	return routeResource, false
}

// -------------- Wait Functions --------------

// WaitForOperatorReady check operator status in OperandRequest
func WaitForOperatorReady(ctx context.Context, k8sClient client.Client, opreqName, ns string) error {
	return wait.PollUntilContextTimeout(ctx, 30*time.Second, 10*time.Minute, false, func(ctx context.Context) (bool, error) {
		operandRequest := &odlm.OperandRequest{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: opreqName, Namespace: ns}, operandRequest); err != nil {
			if k8serrors.IsNotFound(err) {
				klog.V(2).Infof("OperandRequest %s not found in namespace %s", opreqName, ns)
				return false, nil
			}
			klog.ErrorS(err, "Failed to get OperandRequest", "OperandRequest", opreqName)
			return false, err
		}

		klog.Infof("Waiting for all operators to be %s...", resources.PhaseRunning)

		if operandRequest.Status.Phase == resources.PhaseRunning {
			klog.Infof("All operators are running in namespace %s.", ns)
			return true, nil
		}

		return false, nil
	})
}

// WaitForOperandReady checks if all services in OperandRequest are ready
func WaitForOperandReady(ctx context.Context, k8sClient client.Client, opreqName, ns string) error {
	return wait.PollUntilContextTimeout(ctx, 60*time.Second, 10*time.Minute, false, func(ctx context.Context) (bool, error) {
		operandRequest := &odlm.OperandRequest{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: opreqName, Namespace: ns}, operandRequest); err != nil {
			return false, err
		}

		allReady := true
		for _, service := range operandRequest.Status.Services {
			if service.Status != resources.StatusReady {
				klog.Infof("Service %s in namespace %s is not Ready. Current status: %s", service.OperatorName, service.Namespace, service.Status)
				allReady = false
			}
		}

		if allReady {
			klog.Infof("All services in OperandRequest %s in namespace %s are Ready", opreqName, ns)
			return true, nil
		}

		return false, nil
	})
}

// waitForResource waits for the resource to be completed
func WaitForRediscp(ctx context.Context, k8sClient client.Client, ns, name, group, kind, version, compStatus string) error {
	return wait.PollUntilContextTimeout(ctx, 30*time.Second, 10*time.Minute, false, func(ctx context.Context) (bool, error) {
		redisCR := NewUnstructured(group, kind, version)
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, redisCR); err != nil {
			if k8serrors.IsNotFound(err) {
				klog.V(2).Infof("Redis CR %s not found in namespace %s", name, ns)
				return false, nil
			}
			klog.ErrorS(err, "Failed to get Redis CR", "Redis CR", name)
			return false, err
		}

		// need to check if redisCR.Status.RedisStatus is completed
		if redisCR.Object != nil {
			if redisCR.Object["status"] != nil {
				if redisCR.Object["status"].(map[string]interface{})["redisStatus"] == compStatus {
					klog.Infof("Rediscp CR %s in namespace %s is completed", name, ns)
					return true, nil
				}
			}
		}

		klog.Infof("Rediscp CR %s in namespace %s is not completed yet...", name, ns)
		return false, nil
	})
}

// WaitForDeploymentReady waits for the deployment to be ready
func WaitForDeploymentReady(ctx context.Context, k8sClient client.Client, ns, label string) error {
	return wait.PollUntilContextTimeout(ctx, 20*time.Second, 10*time.Minute, false, func(ctx context.Context) (bool, error) {
		deployments := &appsv1.DeploymentList{}

		if err := k8sClient.List(ctx, deployments, &client.ListOptions{Namespace: ns}); err != nil {
			klog.V(2).ErrorS(err, "Failed to get deployment", "deployment", label)
			return false, nil
		}

		var matchedDeployment *appsv1.Deployment
		for _, deployment := range deployments.Items {
			if strings.HasPrefix(deployment.Name, label) {
				matchedDeployment = &deployment
				break
			}
		}

		if matchedDeployment == nil {
			klog.Infof("No deployment found with prefix %s in namespace %s", label, ns)
			return false, nil
		}

		klog.Infof("Waiting for Deployment %s to be ready...", label)

		desiredReplicas := *matchedDeployment.Spec.Replicas
		readyReplicas := matchedDeployment.Status.ReadyReplicas

		if readyReplicas == desiredReplicas {
			klog.Infof("Deployment %s is ready with %d/%d replicas.", label, readyReplicas, desiredReplicas)
			return true, nil
		}

		return false, nil
	})
}

// WaitForJob waits for the job to be succeeded
func WaitForJob(ctx context.Context, k8sClient client.Client, ns, name string) error {
	return wait.PollUntilContextTimeout(ctx, 20*time.Second, 2*time.Minute, false, func(ctx context.Context) (bool, error) {
		job := &batchv1.Job{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, job); err != nil {
			if k8serrors.IsNotFound(err) {
				klog.V(2).Infof("Job %s not found in namespace %s", name, ns)
				return false, nil
			}
			klog.ErrorS(err, "Failed to get Job", "Job", name)
			return false, err
		}

		klog.Infof("Waiting for Job %s to be ready...", name)

		if job.Status.Succeeded > 0 {
			klog.Infof("Job %s is succeeded.", name)
			return true, nil
		}

		return false, nil
	})
}
