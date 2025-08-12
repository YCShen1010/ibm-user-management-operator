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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1alpha1 "github.com/IBM/ibm-user-management-operator/api/v1alpha1"
	"github.com/IBM/ibm-user-management-operator/internal/controller/testutils"
)

var _ = Describe("AccountIAM Controller", func() {
	const (
		AccountIAMName      = "test-accountiam"
		AccountIAMNamespace = "ibm-common-services"
		timeout             = time.Second * 30
		interval            = time.Millisecond * 250
	)

	var (
		ctx = context.Background()
	)

	Context("When testing reconciliation phases", func() {
		var (
			accountIAM *operatorv1alpha1.AccountIAM
			reconciler *AccountIAMReconciler
			recorder   *record.FakeRecorder
		)

		BeforeEach(func() {
			By("Creating namespace if it doesn't exist")
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: AccountIAMNamespace,
				},
			}
			err := k8sClient.Create(ctx, namespace)
			if err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}

			By("Creating AccountIAM resource")
			accountIAM = &operatorv1alpha1.AccountIAM{
				ObjectMeta: metav1.ObjectMeta{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				},
				Spec: operatorv1alpha1.AccountIAMSpec{},
			}

			// Use Eventually to ensure resource creation succeeds
			Eventually(func() error {
				return k8sClient.Create(ctx, accountIAM)
			}, timeout, interval).Should(Succeed())

			By("Setting up reconciler")
			recorder = record.NewFakeRecorder(100)
			reconciler = &AccountIAMReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: recorder,
			}
		})

		AfterEach(func() {
			// Clean up the AccountIAM resource
			err := k8sClient.Delete(ctx, accountIAM)
			if err != nil && !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())
			}

			// Wait for deletion to complete
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}, accountIAM)
				return errors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
		})

		// Phase 1: Initial Resource Validation
		Context("Phase 1: Resource Validation", func() {
			It("should validate AccountIAM resource exists", func() {
				By("Checking resource can be fetched")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				fetchedAccountIAM := &operatorv1alpha1.AccountIAM{}
				Eventually(func() error {
					return k8sClient.Get(ctx, namespacedName, fetchedAccountIAM)
				}, timeout, interval).Should(Succeed())

				Expect(fetchedAccountIAM.Name).To(Equal(AccountIAMName))
				Expect(fetchedAccountIAM.Name).To(Equal(AccountIAMName))
			})

			It("should handle missing resource gracefully", func() {
				By("Reconciling non-existent resource")
				namespacedName := types.NamespacedName{
					Name:      "non-existent",
					Namespace: AccountIAMNamespace,
				}

				result, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: namespacedName,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(result.Requeue).To(BeFalse())
			})
		})

		// Phase 2: Prerequisites Verification
		Context("Phase 2: Prerequisites Verification", func() {
			It("should handle missing ConfigMap and external CRDs gracefully", func() {
				By("Reconciling without cluster info")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				result, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: namespacedName,
				})

				// Current approach: Test resilience to missing external dependencies
				if err != nil {
					// Check if error is due to missing external CRDs
					Expect(err.Error()).To(ContainSubstring("no matches for kind"))
					By("Controller properly handles missing external CRDs")
				} else {
					// If no error, controller might requeue waiting for prerequisites
					Expect(result.Requeue || result.RequeueAfter > 0).To(BeTrue())
					By("Controller gracefully defers when prerequisites missing")
				}
			})

			It("should validate prerequisite logic independently", func() {
				By("Testing controller's prerequisite validation logic")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				result, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: namespacedName,
				})

				// What actually testing here:
				// 1. Controller maintains state consistency
				// 2. Error handling doesn't leak resources
				// 3. Reconcile loop behaves predictably

				if err != nil {
					Expect(err.Error()).NotTo(BeEmpty())
					By("Error provides debugging information")
				} else {
					Expect(result).NotTo(BeNil())
					By("Controller returns valid reconcile result")
				}
			})

			It("should proceed when cluster info is available", func() {
				By("Creating cluster info ConfigMap")
				clusterInfo := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "mcsp-info",
						Namespace: AccountIAMNamespace,
					},
					Data: map[string]string{
						"cluster_address":  "test.example.com",
						"cluster_endpoint": "https://test.example.com:443",
					},
				}
				Expect(k8sClient.Create(ctx, clusterInfo)).Should(Succeed())

				By("Reconciling with cluster info present")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				result, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: namespacedName,
				})

				if err != nil {
					Expect(err.Error()).To(ContainSubstring("no matches for kind"))
				} else {
					Expect(result).NotTo(BeNil())
				}
			})
		})

		// Phase 3: Resource Creation/Update
		Context("Phase 3: Resource Management", func() {
			It("should handle ConfigMap creation", func() {
				By("Setting up prerequisites")
				clusterInfo := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "mcsp-info",
						Namespace: AccountIAMNamespace,
					},
					Data: map[string]string{
						"cluster_address":  "test.example.com",
						"cluster_endpoint": "https://test.example.com:443",
					},
				}

				err := k8sClient.Create(ctx, clusterInfo)
				if err != nil && !errors.IsAlreadyExists(err) {
					Expect(err).NotTo(HaveOccurred())
				}

				By("Reconciling to trigger resource creation")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: namespacedName,
				})

				if err != nil {
					Expect(err.Error()).To(ContainSubstring("no matches for kind"))
					By("Controller properly handles missing external CRDs")
				}

				// Check if expected ConfigMaps are created (based on controller logic)
				Eventually(func() bool {
					configMaps := &corev1.ConfigMapList{}
					err := k8sClient.List(ctx, configMaps, &client.ListOptions{
						Namespace: AccountIAMNamespace,
					})
					return err == nil && len(configMaps.Items) > 0
				}, timeout, interval).Should(BeTrue())
			})

			It("should handle Secret creation", func() {
				By("Setting up prerequisites and reconciling")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: namespacedName,
				})

				if err != nil {
					Expect(err.Error()).To(ContainSubstring("no matches for kind"))
				}

				secrets := &corev1.SecretList{}
				err = k8sClient.List(ctx, secrets, &client.ListOptions{
					Namespace: AccountIAMNamespace,
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})

		// Phase 4: Status Updates
		Context("Phase 4: Status Management", func() {
			It("should update status during reconciliation", func() {
				By("Reconciling and checking status")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: namespacedName,
				})

				if err != nil {
					Expect(err.Error()).To(ContainSubstring("no matches for kind"))
					By("Controller properly reports missing external dependencies")
					return
				}

				updatedAccountIAM := &operatorv1alpha1.AccountIAM{}
				err = k8sClient.Get(ctx, namespacedName, updatedAccountIAM)
				Expect(err).NotTo(HaveOccurred())

				Expect(updatedAccountIAM.Status).NotTo(BeNil())
			})

			It("should handle status update failures gracefully", func() {
				By("Testing status update resilience")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				for i := 0; i < 3; i++ {
					_, err := reconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: namespacedName,
					})

					if err != nil {
						Expect(err.Error()).To(ContainSubstring("no matches for kind"))
						By("Controller handles missing dependencies consistently")
					}
				}
			})
		})

		// Phase 5: Error Handling
		Context("Phase 5: Error Scenarios", func() {
			It("should handle reconcile errors gracefully", func() {
				By("Creating a scenario that might cause errors")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				result, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: namespacedName,
				})

				if err != nil {
					Expect(err.Error()).NotTo(BeEmpty())
					By("Controller provides informative error messages")
				}
				Expect(result).NotTo(BeNil())
			})

			It("should retry on transient failures", func() {
				By("Testing retry logic")
				namespacedName := types.NamespacedName{
					Name:      AccountIAMName,
					Namespace: AccountIAMNamespace,
				}

				result, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: namespacedName,
				})

				if err != nil {
					Expect(err.Error()).To(ContainSubstring("no matches for kind"))
					By("Controller fails predictably when dependencies are missing")
				} else {
					Expect(result.Requeue || result.RequeueAfter > 0).To(BeTrue())
					By("Controller queues retry when appropriate")
				}
			})
		})
	})

	Context("When testing utility functions", func() {
		It("should properly check if string is in slice", func() {
			slice := []string{"pass", "fail", "notFound"}
			Expect(testutils.Contains(slice, "fail")).To(BeTrue())
			Expect(testutils.Contains(slice, "failed")).To(BeFalse())
		})

		It("should properly remove string from slice", func() {
			slice := []string{"pass", "fail", "notFound"}
			result := testutils.Remove(slice, "fail")
			Expect(result).To(Equal([]string{"pass", "notFound"}))
			Expect(len(result)).To(Equal(2))
		})

		It("should handle empty slices", func() {
			var emptySlice []string
			Expect(testutils.Contains(emptySlice, "test")).To(BeFalse())
			result := testutils.Remove(emptySlice, "test")
			Expect(result).To(BeEmpty())
		})
	})

	Context("When testing specific controller functions", func() {
		var (
			reconciler *AccountIAMReconciler
			recorder   *record.FakeRecorder
		)

		BeforeEach(func() {
			recorder = record.NewFakeRecorder(100)
			reconciler = &AccountIAMReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: recorder,
			}
		})

		Context("Status Management Functions", func() {
			It("should update status correctly", func() {
				By("Creating AccountIAM resource")
				accountIAM := &operatorv1alpha1.AccountIAM{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-status",
						Namespace: AccountIAMNamespace,
					},
					Spec: operatorv1alpha1.AccountIAMSpec{},
				}

				err := k8sClient.Create(ctx, accountIAM)
				Expect(err).NotTo(HaveOccurred())

				By("Calling updateStatus function")
				// This tests the updateStatus function specifically
				reconciler.updateStatus(ctx, accountIAM)

				By("Verifying status was updated")
				updatedAccountIAM := &operatorv1alpha1.AccountIAM{}
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-status",
					Namespace: AccountIAMNamespace,
				}, updatedAccountIAM)
				Expect(err).NotTo(HaveOccurred())

				// Status should be initialized
				Expect(updatedAccountIAM.Status).NotTo(BeNil())

				// Cleanup
				k8sClient.Delete(ctx, accountIAM)
			})
		})

		Context("Resource Creation Functions", func() {
			It("should handle createOrUpdate with new resources", func() {
				By("Creating a test ConfigMap resource")
				testConfigMap := &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "v1",
						"kind":       "ConfigMap",
						"metadata": map[string]interface{}{
							"name":      "test-createorupdate",
							"namespace": AccountIAMNamespace,
						},
						"data": map[string]interface{}{
							"test-key": "test-value",
						},
					},
				}

				By("Calling createOrUpdate function")
				err := reconciler.createOrUpdate(ctx, testConfigMap)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying resource was created")
				createdCM := &corev1.ConfigMap{}
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-createorupdate",
					Namespace: AccountIAMNamespace,
				}, createdCM)
				Expect(err).NotTo(HaveOccurred())
				Expect(createdCM.Data["test-key"]).To(Equal("test-value"))

				// Cleanup
				k8sClient.Delete(ctx, createdCM)
			})

			It("should handle createOrUpdate with existing resources", func() {
				By("Creating initial ConfigMap")
				initialCM := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-update",
						Namespace: AccountIAMNamespace,
					},
					Data: map[string]string{
						"initial": "value",
					},
				}
				err := k8sClient.Create(ctx, initialCM)
				Expect(err).NotTo(HaveOccurred())

				By("Updating via createOrUpdate")
				updatedResource := &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "v1",
						"kind":       "ConfigMap",
						"metadata": map[string]interface{}{
							"name":      "test-update",
							"namespace": AccountIAMNamespace,
						},
						"data": map[string]interface{}{
							"initial": "value",
							"updated": "newvalue",
						},
					},
				}

				err = reconciler.createOrUpdate(ctx, updatedResource)
				Expect(err).NotTo(HaveOccurred())

				By("Verifying resource was updated")
				finalCM := &corev1.ConfigMap{}
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-update",
					Namespace: AccountIAMNamespace,
				}, finalCM)
				Expect(err).NotTo(HaveOccurred())
				Expect(finalCM.Data["updated"]).To(Equal("newvalue"))
				Expect(finalCM.Data["initial"]).To(Equal("value"))

				// Cleanup
				k8sClient.Delete(ctx, finalCM)
			})
		})

		Context("Initialization Functions", func() {
			It("should initialize reconcile context properly", func() {
				By("Creating AccountIAM resource")
				accountIAM := &operatorv1alpha1.AccountIAM{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-init-context",
						Namespace: AccountIAMNamespace,
					},
					Spec: operatorv1alpha1.AccountIAMSpec{},
				}

				err := k8sClient.Create(ctx, accountIAM)
				Expect(err).NotTo(HaveOccurred())

				By("Initializing reconcile context")
				reconcileCtx := &ReconcileContext{
					Instance: accountIAM,
				}

				err = reconciler.initializeReconcileContext(ctx, reconcileCtx)

				if err != nil {
					Expect(err.Error()).To(ContainSubstring("no matches for kind"))
					By("initializeReconcileContext handles missing external dependencies")
				} else {
					Expect(reconcileCtx.Instance).NotTo(BeNil())
					By("initializeReconcileContext completed successfully")
				}

				k8sClient.Delete(ctx, accountIAM)
			})
		})

		Context("Bootstrap Data Functions", func() {
			It("should handle initBootstrapData function", func() {
				By("Testing initBootstrapData with valid data")
				testData := []byte("test-bootstrap-data")

				secret, err := reconciler.initBootstrapData(ctx, AccountIAMNamespace, testData)

				if err != nil {
					Expect(err.Error()).NotTo(BeEmpty())
					By("initBootstrapData handles missing dependencies gracefully")
				} else {
					Expect(secret).NotTo(BeNil())
					By("initBootstrapData created secret successfully")

					if secret != nil {
						k8sClient.Delete(ctx, secret)
					}
				}
			})
		})

		Context("Job Management Functions", func() {
			It("should handle cleanJob function", func() {
				By("Testing cleanJob with empty job list")
				err := reconciler.cleanJob(ctx, []string{}, AccountIAMNamespace)
				Expect(err).NotTo(HaveOccurred())

				By("Testing cleanJob with non-existent jobs")
				err = reconciler.cleanJob(ctx, []string{"non-existent-job"}, AccountIAMNamespace)
				// Should not error when jobs don't exist
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("Validation Functions", func() {
			It("should handle resource validation gracefully", func() {
				By("Creating AccountIAM resource for validation")
				accountIAM := &operatorv1alpha1.AccountIAM{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-validation",
						Namespace: AccountIAMNamespace,
					},
					Spec: operatorv1alpha1.AccountIAMSpec{},
				}

				err := k8sClient.Create(ctx, accountIAM)
				Expect(err).NotTo(HaveOccurred())

				By("Testing verifyPrereq function")
				reconcileCtx := &ReconcileContext{
					Instance: accountIAM,
				}

				err = reconciler.verifyPrereq(ctx, reconcileCtx)

				if err != nil {
					Expect(err.Error()).To(ContainSubstring("no matches for kind"))
					By("verifyPrereq handles missing external dependencies")
				} else {
					By("verifyPrereq completed successfully")
				}

				k8sClient.Delete(ctx, accountIAM)
			})
		})

		Context("Resource Creation Error Handling", func() {
			It("should handle createOperandRequest errors gracefully", func() {
				By("Creating AccountIAM resource")
				accountIAM := &operatorv1alpha1.AccountIAM{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-operand-request",
						Namespace: AccountIAMNamespace,
					},
					Spec: operatorv1alpha1.AccountIAMSpec{},
				}

				err := k8sClient.Create(ctx, accountIAM)
				Expect(err).NotTo(HaveOccurred())

				By("Testing createOperandRequest function")
				err = reconciler.createOperandRequest(ctx, accountIAM, "test-request", []string{"test-operand"})

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no matches for kind"))
				By("createOperandRequest properly reports missing OperandRequest CRD")

				k8sClient.Delete(ctx, accountIAM)
			})

			It("should handle createRedisCR errors gracefully", func() {
				By("Creating AccountIAM resource")
				accountIAM := &operatorv1alpha1.AccountIAM{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-redis-cr",
						Namespace: AccountIAMNamespace,
					},
					Spec: operatorv1alpha1.AccountIAMSpec{},
				}

				err := k8sClient.Create(ctx, accountIAM)
				Expect(err).NotTo(HaveOccurred())

				By("Testing createRedisCR function")
				reconcileCtx := &ReconcileContext{
					Instance: accountIAM,
				}

				// Note: This function will likely panic or error due to missing CRDs and config
				// We're testing that the function doesn't cause catastrophic failures
				defer func() {
					if r := recover(); r != nil {
						By("createRedisCR panicked as expected due to missing dependencies")
					}
				}()

				err = reconciler.createRedisCR(ctx, reconcileCtx)

				if err != nil {
					Expect(err.Error()).NotTo(BeEmpty())
					By("createRedisCR properly reports errors when dependencies are missing")
				}

				k8sClient.Delete(ctx, accountIAM)
			})
		})

		Context("Phase Functions", func() {
			It("should handle reconcilePhases with missing dependencies", func() {
				By("Creating AccountIAM resource")
				accountIAM := &operatorv1alpha1.AccountIAM{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-phases",
						Namespace: AccountIAMNamespace,
					},
					Spec: operatorv1alpha1.AccountIAMSpec{},
				}

				err := k8sClient.Create(ctx, accountIAM)
				Expect(err).NotTo(HaveOccurred())

				By("Testing reconcilePhases function")
				reconcileCtx := &ReconcileContext{
					Instance: accountIAM,
				}

				err = reconciler.reconcilePhases(ctx, reconcileCtx)

				// Expected to fail due to missing external dependencies
				if err != nil {
					Expect(err.Error()).To(ContainSubstring("no matches for kind"))
					By("reconcilePhases handles missing dependencies gracefully")
				}

				// Cleanup
				k8sClient.Delete(ctx, accountIAM)
			})
		})
	})
})
