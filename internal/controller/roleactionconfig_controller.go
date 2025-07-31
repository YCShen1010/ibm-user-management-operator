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
	"context"
	goerrors "errors"
	"net/http"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	logger "github.com/rs/zerolog/log" // TODO: investigate if this is really necessary

	operatorv1alpha1 "github.com/IBM/ibm-user-management-operator/api/v1alpha1"
	"github.com/IBM/ibm-user-management-operator/client/account_iam"
)

// RoleActionConfigReconciler reconciles a RoleActionConfig object
type RoleActionConfigReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient account_iam.IAMClient
}

const (
	WatchNamespace = "WATCH_NAMESPACE"
)

var (
	log                     = logf.Log.WithName("controller_roleactionconfig")
	IAMServiceEndpoint      = ""
	IAMProductRolesEndpoint = ""
)

func (r *RoleActionConfigReconciler) PreReq(instance *operatorv1alpha1.RoleActionConfig) error {
	if _, ok := r.APIClient.(*account_iam.MCSPIAMClient); !ok {
		err := goerrors.New("the MCSPIAMClient type does not implement IAMClient") // this should never happen unless code was modified incorrectly
		return err
	}

	mcspApiClient := r.APIClient.(*account_iam.MCSPIAMClient)

	namespace := ""

	accountIAMs := &operatorv1alpha1.AccountIAMList{}
	selector := labels.SelectorFromSet(labels.Set{
		"operator.ibm.com/opreq-control": "true",
	})
	if err := r.Client.List(context.TODO(), accountIAMs, &client.ListOptions{
		LabelSelector: selector,
	}); err != nil {
		return err
	}
	if len(accountIAMs.Items) == 0 {
		return goerrors.New("no account-iam exists yet, waiting")
	}

	namespace = accountIAMs.Items[0].Namespace
	if len(accountIAMs.Items) > 1 { // if installing with ODLM, this should not happen
		// if more than one account-iam svc, then rely on label in RoleActionConfig CR
		if _, ok := instance.Labels["operator.ibm.com/account-iam-ns"]; !ok {
			return goerrors.New("found more than one AccountIAM CR and missing 'operator.ibm.com/operator.ibm.com/account-iam-ns' label")
		}
		namespace = instance.Labels["operator.ibm.com/operator.ibm.com/account-iam-ns"]
	}

	if IAMServiceEndpoint == "" {
		// fetch namespace of account-iam service
		IAMServiceEndpoint = "https://account-iam." + namespace + ".svc.cluster.local:9445/api/2.0/accounts/global_account/apikeys/token"
	}

	if IAMProductRolesEndpoint == "" {
		// fetch namespace of account-iam service
		IAMProductRolesEndpoint = "https://account-iam." + namespace + ".svc.cluster.local:9445/api/2.0/products"
		mcspApiClient.BaseURL = IAMProductRolesEndpoint
	}

	if mcspApiClient.ApiKey == "" {
		// fetch from mcsp-im-integration-details secret
		secret := &corev1.Secret{}
		if err := r.Client.Get(context.TODO(), types.NamespacedName{
			Name:      "mcsp-im-integration-details",
			Namespace: namespace,
		}, secret); err != nil {
			return err
		}
		if _, ok := secret.Data["API_KEY"]; !ok {
			return goerrors.New("secret mcsp-im-integration-details missing API_KEY")
		}
		mcspApiClient.ApiKey = string(secret.Data["API_KEY"])
	}
	return nil
}

// +kubebuilder:rbac:groups=operator.ibm.com,namespace="placeholder",resources=roleactionconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=operator.ibm.com,namespace="placeholder",resources=roleactionconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=operator.ibm.com,namespace="placeholder",resources=roleactionconfigs/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the RoleActionConfig object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.18.4/pkg/reconcile
func (r *RoleActionConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)
	reqLogger.Info("Reconciling Product Registration Controller")

	namespace := os.Getenv(WatchNamespace)
	reqLogger.Info(namespace)

	reqLogger.Info("CR triggered")

	// Fetch the ProductRegistrationV2 CR instance
	instance := &operatorv1alpha1.RoleActionConfig{}

	err := r.Client.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	if err := r.PreReq(instance); err != nil {
		return ctrl.Result{}, err
	}

	// Fetch serviceID, v2CustomRoles, product level actions fields.
	serviceID := instance.Spec.ServiceID
	v2CustomRolesSection := instance.Spec.IAM.V2CustomRoles
	crActionsProductLevel := instance.Spec.IAM.Actions

	// POST request to account IAM /api/2.0/accounts/global_account/apikeys/token.
	IAMServiceEndpoint := IAMServiceEndpoint

	_, err = r.APIClient.GetToken(IAMServiceEndpoint)
	if err != nil {
		log.Error(err, "failed to get token")
		return ctrl.Result{}, nil
	}

	var UIDs map[string]string
	var getUIDstatusCode int

	// GET request to account IAM /api/2.0/products/{productId} to get product details and see if it exists in account IAM.
	// Note: account IAM "productId" is product reg yaml "serviceId"

	_, getProductDetailsStatusCode, err := r.APIClient.GetProductDetails(serviceID)
	if err != nil {
		log.Error(err, "Failed to GET product details from Account IAM.")
	} else {
		logger.Info().Msgf("Successfully made request to GET product details API call. Status Code: %d", getProductDetailsStatusCode)
	}

	// Check if the product has been registered on Account IAM.
	// If response is 404, product is unknown to Account IAM and we need to register the product.
	if getProductDetailsStatusCode == http.StatusNotFound {
		logger.Info().Msgf("Product %s not found in Account IAM (Status Code: %d). Proceed to make POST request to register the product.", req.Name, getProductDetailsStatusCode)

		postNewProduct, postNewProductStatusCode, err := r.APIClient.PostNewProduct(serviceID)

		if err != nil {
			log.Error(err, "Failed to POST and register new product to Account IAM.")
		} else {
			logger.Info().Msgf("Successfully made POST request to register product %s to Account IAM. Status: %s, Status Code: %d", serviceID, string(postNewProduct), postNewProductStatusCode)
		}
	}

	// Check if V2CustomRoles field exists before executing API calls
	if v2CustomRolesSection != nil {

		// Get all custom roles by GET request to account IAM /api/2.0/products/{scopeId}/roles API.
		UIDs, getUIDstatusCode, err = r.APIClient.GetUID(instance)
		if err != nil {
			log.Error(err, "failed to do GET request to product custom roles API.")
			return ctrl.Result{}, nil
		}
		// Log the status of the GET request
		logger.Info().Msgf("Successfully made request to GET product custom roles API. Status Code: %d", getUIDstatusCode)

		// Check if the product has been registered on Account IAM
		if getUIDstatusCode == http.StatusNotFound {
			logger.Info().Msgf("Product %s not found in Account IAM (Status Code: %d). No further actions needed.", req.Name, getUIDstatusCode)
		}

		for _, v2CustomRole := range instance.Spec.IAM.V2CustomRoles {
			// When account IAM returns a status code of 404 (not found), product is not registered with AccountIAM therefore we don't need to execute these requests.
			if getUIDstatusCode != http.StatusNotFound {
				// Create custom role by POST request to account IAM /api/2.0/products API.
				customRoles, postStatusCode, err := r.APIClient.PostCustomRoles(v2CustomRole, serviceID)

				if err != nil {
					log.Error(err, "failed to do POST request to product custom roles API.")
				}

				logger.Info().Msgf("Successfully made request to POST product custom roles API. Status Message: %s. Status Code: %d", string(customRoles), postStatusCode)

				// Update custom roles by PATCH request to account IAM /api/2.0/products API.
				updateCustomRoles, updateStatusCode, err := r.APIClient.UpdateCustomRoles(v2CustomRole, serviceID, UIDs[v2CustomRole.Name])

				if err != nil {
					log.Error(err, "failed to do PATCH request to product custom roles API.")
				}

				logger.Info().Msgf("Successfully made request to PATCH product custom roles API. Status Message: %s. Status Code: %d", string(updateCustomRoles), updateStatusCode)
			}

			// Delete custom roles by DELETE request to account IAM /api/2.0/products API.
			if len(UIDs) > 0 && getUIDstatusCode != http.StatusNotFound {
				for name, UID := range UIDs {
					var found bool
					for _, v2CustomRole := range instance.Spec.IAM.V2CustomRoles {
						if name == v2CustomRole.Name {
							found = true
						}
					}

					if !found {
						deleteCustomRoles, statusCode, err := r.APIClient.DeleteCustomRoles(instance, UID)

						if err != nil {
							log.Error(err, "failed to do DELETE request to product custom roles API.")
						}

						logger.Info().Msgf("Successfully made request to DELETE product custom roles API. Status Message: %s. Status Code: %d", string(deleteCustomRoles), statusCode)
					}
				}
			}
		}
	}
	// Check if actions at product level exists before executing API calls
	if crActionsProductLevel != nil {
		// GET all product level actions from account IAM /api/2.0/products/{scopeId}/actions API.
		getActionsProductLevel, getStatusCode, err := r.APIClient.GetActionsProductLevel(serviceID)
		if err != nil {
			log.Error(err, "failed to do GET list actions API.")
		}
		// Log the status of the GET request
		logger.Info().Msgf("Successfully made request to GET product list actions API. Status Code: %d", getStatusCode)

		// Check if the product has been registered on Account IAM
		if getStatusCode == http.StatusNotFound {
			logger.Info().Msgf("Product %s not found in Account IAM (Status Code: %d). No further actions needed.", req.Name, getStatusCode)
		}

		if getStatusCode != http.StatusNotFound {
			// Format GET response with list of actions
			actionsProductLevel := sets.New[string]()
			for _, singleItem := range getActionsProductLevel {
				actionsProductLevel.Insert(singleItem["name"])
			}

			// Format product registration list of actions
			productRegistrationActions := sets.New[string]()
			for _, action := range instance.Spec.IAM.Actions {
				productRegistrationActions.Insert(action)
			}
			// Find the differences between IAM list of actions and product registration list of actions
			diff := actionsProductLevel.Difference(productRegistrationActions)
			diff2 := productRegistrationActions.Difference(actionsProductLevel)
			for actionProductLevel := range diff2 {
				// POST request to account IAM /api/2.0/products/{scopeId}/actions API.

				postActionsProductLevel, statusCode, err := r.APIClient.PostActionsProductLevel(actionProductLevel, serviceID)
				if err != nil {
					log.Error(err, "failed to do POST request to product level actions API.")
				}

				logger.Info().Msgf("Successfully made request to POST product level actions API. Status Message: %s. Status Code: %d", string(postActionsProductLevel), statusCode)
			}
			// DELETE request to account IAM /api/2.0/products/{scopeId}/actions/{action} API with actions removed from product registration.
			for actionName := range diff {
				deleteActionsProductLevel, statusCode, err := r.APIClient.DeleteActionsProductLevel(serviceID, actionName)
				if err != nil {
					log.Error(err, "failed to do DELETE request to list actions API.")
				}
				logger.Info().Msgf("Successfully made request to DELETE list actions API. Status Message: %s. Status Code: %d", string(deleteActionsProductLevel), statusCode)
			}
		}
		// Check if actions at custom role level exists before executing API calls
		for _, v2CustomRole := range instance.Spec.IAM.V2CustomRoles {
			if v2CustomRole.Actions != nil && getUIDstatusCode != http.StatusNotFound {
				// GET all role level actions from account IAM /api/2.0/products/{scopeId}/roles/{roleUid}/actions API.
				getActionsRoleLevel, statusCode, err := r.APIClient.GetActionsRoleLevel(serviceID, UIDs[v2CustomRole.Name])

				if err != nil {
					log.Error(err, "failed to do GET list actions at role level API.")
				}
				logger.Info().Msgf("Successfully made request to GET list actions at role level API. Status Code: %d", statusCode)

				// Format GET response with list of role actions
				actionsRoleLevel := sets.New[string]()
				for _, singleItem := range getActionsRoleLevel {
					actionsRoleLevel.Insert(singleItem["name"])
				}

				// Format product registration list of role actions
				productRegistrationActions := sets.New[string]()
				for _, action := range v2CustomRole.Actions {
					productRegistrationActions.Insert(serviceID + "." + action)
				}

				// Find the differences between product registration list of role actions and IAM list of role actions
				diff := productRegistrationActions.Difference(actionsRoleLevel)
				for actionRoleLevel := range diff {
					// POST request to account IAM  /api/2.0/products/{scopeId}/roles/{roleUid}/actions API.
					postActionsRoleLevel, statusCode, err := r.APIClient.PostActionsRoleLevel(actionRoleLevel, UIDs[v2CustomRole.Name], serviceID)
					if err != nil {
						log.Error(err, "failed to do POST request to role level actions API.")
					}
					logger.Info().Msgf("Successfully made request to POST role level actions API. Status Message: %s. Status Code: %d", string(postActionsRoleLevel), statusCode)
				}
				// Find the differences between IAM list of role actions and product registration list of role actions
				diff = actionsRoleLevel.Difference(productRegistrationActions)

				for actionRoleLevel := range diff {
					// DELETE request to account IAM /api/2.0/products/{scopeId}/roles/{roleUid}/actions/{action} API.
					deleteActionsProductLevel, statusCode, err := r.APIClient.DeleteActionsRoleLevel(serviceID, UIDs[v2CustomRole.Name], actionRoleLevel)
					if err != nil {
						log.Error(err, "failed to do DELETE request to role level actions API.")
					}
					logger.Info().Msgf("Successfully made request to DELETE role level actions API. Status Message: %s. Status Code: %d", string(deleteActionsProductLevel), statusCode)
				}

			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RoleActionConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&operatorv1alpha1.RoleActionConfig{}).
		Complete(r)
}
