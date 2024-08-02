package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/IBM/ibm-user-management-operator/internal/resources"
	odlm "github.com/IBM/operand-deployment-lifecycle-manager/v4/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ImageList = []string{"MCSP_UTILS_IMAGE", "ACCOUNT_IAM_APP_IMAGE", "MCSP_IM_CONFIG_JOB_IMAGE", "ACCOUNT_IAM_UI_INSTANCE_SERVICE_IMAGE", "ACCOUNT_IAM_UI_API_SERVICE_IMAGE"}
)

// NewUnstructured return Unstructured object
func NewUnstructured(group, kind, version string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   group,
		Kind:    kind,
		Version: version})
	return u
}

func generatePassword(len int) ([]byte, error) {
	random := make([]byte, len)
	_, err := rand.Read(random)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(random)
	encoded2 := base64.StdEncoding.EncodeToString([]byte(encoded))
	result := []byte(encoded2)
	return result, nil
}

func concat(s ...string) string {
	return strings.Join(s, "")
}

func replaceImages(resource string) (result string) {
	result = resource
	for _, imageName := range ImageList {
		result = strings.ReplaceAll(result, imageName, getImage(imageName))
	}
	return result
}

func getImage(imageName string) string {
	image, _ := os.LookupEnv(imageName)
	return image
}

// GetSecretData gets the data from a secret
func getSecretData(ctx context.Context, k8sClient client.Client, secretName, ns, dataKey string) (string, error) {
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

// InsertColonInRedisURL inserts colon in the redis URL SSL
func insertColonInURL(redisURL string) string {
	parts := strings.SplitN(redisURL, "@", 2)
	if len(parts) == 2 {
		parts[0] = strings.Replace(parts[0], "rediss://", "rediss://:", 1)
		return parts[0] + "@" + parts[1]
	}
	return redisURL
}

// waitForOperatorReady check operator status in OperandRequest
func waitForOperatorReady(ctx context.Context, k8sClient client.Client, opreqName, ns string) error {
	return wait.PollImmediate(30*time.Second, 10*time.Minute, func() (bool, error) {
		operandRequest := &odlm.OperandRequest{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: opreqName, Namespace: ns}, operandRequest); err != nil {
			if k8serrors.IsNotFound(err) {
				klog.V(2).Infof("OperandRequest %s not found in namespace %s", opreqName, ns)
				return false, nil
			}
			klog.ErrorS(err, "Failed to get OperandRequest", "OperandRequest", opreqName)
			return false, err
		}

		klog.Infof("Waiting for all operators to be %s...", resources.OpreqPhaseRunning)

		if operandRequest.Status.Phase == resources.OpreqPhaseRunning {
			klog.Infof("All operators are running in namespace %s.", ns)
			return true, nil
		}

		return false, nil
	})
}

// waitForOperandReady checks if all services in OperandRequest are ready
func waitForOperandReady(ctx context.Context, k8sClient client.Client, opreqName, ns string) error {
	return wait.PollImmediate(60*time.Second, 10*time.Minute, func() (bool, error) {
		operandRequest := &odlm.OperandRequest{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: opreqName, Namespace: ns}, operandRequest); err != nil {
			return false, err
		}

		allReady := true
		for _, service := range operandRequest.Status.Services {
			if service.Status != resources.OperandStatusReady {
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
func waitForRediscp(ctx context.Context, k8sClient client.Client, ns, name, group, kind, version, compStatus string) error {
	return wait.PollImmediate(30*time.Second, 10*time.Minute, func() (bool, error) {

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

		klog.Infof("Redis CR %s in namespace %s is not completed yet...", name, ns)
		return false, nil
	})
}

// waitForDeploymentReady waits for the deployment to be ready
func waitForDeploymentReady(ctx context.Context, k8sClient client.Client, ns, label string) error {

	return wait.PollImmediate(20*time.Second, 10*time.Minute, func() (bool, error) {
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

// waitForJob waits for the job to be succeeded
func waitForJob(ctx context.Context, k8sClient client.Client, ns, name string) error {

	return wait.PollImmediate(20*time.Second, 2*time.Minute, func() (bool, error) {
		job := &batchv1.Job{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, job); err != nil {
			klog.V(2).ErrorS(err, "Failed to get job", "job", name)
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
