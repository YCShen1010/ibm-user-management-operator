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

package utils

import (
	"context"
	"encoding/base64"
	"os"
	"time"

	"github.com/IBM/ibm-user-management-operator/internal/resources"
	odlm "github.com/IBM/operand-deployment-lifecycle-manager/v4/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var ctx = context.Background()

var _ = Describe("Utils Functions", func() {

	Context("Environment Functions", func() {
		It("should get operator namespace from environment", func() {
			os.Setenv("OPERATOR_NAMESPACE", "test-operator-ns")
			defer os.Unsetenv("OPERATOR_NAMESPACE")

			ns := GetOperatorNamespace()
			Expect(ns).To(Equal("test-operator-ns"))
		})

		It("should return empty string when OPERATOR_NAMESPACE is not set", func() {
			os.Unsetenv("OPERATOR_NAMESPACE")
			ns := GetOperatorNamespace()
			Expect(ns).To(Equal(""))
		})

		It("should get watch namespace from environment", func() {
			// Test with WATCH_NAMESPACE set
			os.Setenv("WATCH_NAMESPACE", "test-watch-ns")
			defer os.Unsetenv("WATCH_NAMESPACE")

			ns := GetWatchNamespace()
			Expect(ns).To(Equal("test-watch-ns"))
		})

		It("should fallback to operator namespace when WATCH_NAMESPACE is not set", func() {
			os.Unsetenv("WATCH_NAMESPACE")
			os.Setenv("OPERATOR_NAMESPACE", "test-operator-ns")
			defer os.Unsetenv("OPERATOR_NAMESPACE")

			ns := GetWatchNamespace()
			Expect(ns).To(Equal("test-operator-ns"))
		})
	})

	Context("Unstructured Functions", func() {
		It("should create unstructured object with correct GVK", func() {
			u := NewUnstructured("test.group", "TestKind", "v1")
			Expect(u).NotTo(BeNil())

			gvk := u.GetObjectKind().GroupVersionKind()
			Expect(gvk.Group).To(Equal("test.group"))
			Expect(gvk.Kind).To(Equal("TestKind"))
			Expect(gvk.Version).To(Equal("v1"))
		})
	})

	Context("String Utility Functions", func() {
		It("should concatenate strings correctly", func() {
			result := Concat("user", "-", "management", "!")
			Expect(result).To(Equal("user-management!"))
		})

		It("should concatenate empty strings", func() {
			result := Concat("", "", "")
			Expect(result).To(Equal(""))
		})

		It("should concatenate single string", func() {
			result := Concat("UserManagement")
			Expect(result).To(Equal("UserManagement"))
		})
	})

	Context("Random String Functions", func() {
		It("should generate random strings of specified lengths", func() {
			lengths := []int{8, 16, 32}
			results, err := RandStrings(lengths...)

			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(3))

			for _, result := range results {
				Expect(result).NotTo(BeEmpty())
				// Verify it's base64 encoded (double encoded in this case)
				_, err := base64.StdEncoding.DecodeString(string(result))
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should handle zero lengths", func() {
			results, err := RandStrings(0, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(2))
		})

		It("should handle empty input", func() {
			results, err := RandStrings()
			Expect(err).NotTo(HaveOccurred())
			Expect(results).To(HaveLen(0))
		})
	})

	Context("Data Combination Functions", func() {
		type TestStruct1 struct {
			Field1 string
			Field2 int
		}

		type TestStruct2 struct {
			Field3 bool
			Field4 float64
		}

		It("should combine data from multiple structs", func() {
			s1 := TestStruct1{Field1: "test", Field2: 42}
			s2 := TestStruct2{Field3: true, Field4: 3.14}

			result := CombineData(s1, s2)

			Expect(result).To(HaveKey("Field1"))
			Expect(result).To(HaveKey("Field2"))
			Expect(result).To(HaveKey("Field3"))
			Expect(result).To(HaveKey("Field4"))
			Expect(result["Field1"]).To(Equal("test"))
			Expect(result["Field2"]).To(Equal(42))
			Expect(result["Field3"]).To(Equal(true))
			Expect(result["Field4"]).To(Equal(3.14))
		})

		It("should handle pointer structs", func() {
			s1 := &TestStruct1{Field1: "test", Field2: 42}
			result := CombineData(s1)

			Expect(result).To(HaveKey("Field1"))
			Expect(result["Field1"]).To(Equal("test"))
		})

		It("should handle non-struct values gracefully", func() {
			result := CombineData("not a struct", 123, []string{"slice"})
			Expect(result).To(BeEmpty())
		})
	})

	Context("Certificate Indentation Functions", func() {
		It("should indent certificate correctly", func() {
			cert := "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
			indented := IndentCert(cert, 4)

			lines := []string{
				"    -----BEGIN CERTIFICATE-----",
				"    MIIC...",
				"    -----END CERTIFICATE-----",
			}
			expected := lines[0] + "\n" + lines[1] + "\n" + lines[2]
			Expect(indented).To(Equal(expected))
		})

		It("should handle zero indentation", func() {
			cert := "test\ncert"
			result := IndentCert(cert, 0)
			Expect(result).To(Equal("test\ncert"))
		})

		It("should handle single line", func() {
			cert := "single line"
			result := IndentCert(cert, 2)
			Expect(result).To(Equal("  single line"))
		})
	})

	Context("Redis Info Functions", func() {
		It("should parse Redis URL correctly", func() {
			url := "redis://localhost:6380/0"
			host, port, err := GetRedisInfo(url)

			Expect(err).NotTo(HaveOccurred())
			Expect(host).To(Equal("localhost"))
			Expect(port).To(Equal("6380"))
		})

		It("should use default port when not specified", func() {
			url := "redis://localhost/0"
			host, port, err := GetRedisInfo(url)

			Expect(err).NotTo(HaveOccurred())
			Expect(host).To(Equal("localhost"))
			Expect(port).To(Equal("6379"))
		})

		It("should handle invalid URL", func() {
			url := "://invalid"
			_, _, err := GetRedisInfo(url)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Hash Calculation Functions", func() {
		It("should calculate hashes for resources", func() {
			template := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Test",
					"spec": map[string]interface{}{
						"field": "value",
					},
				},
			}

			cluster := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Test",
					"metadata": map[string]interface{}{
						"annotations": map[string]interface{}{
							resources.HashedData: "existing-hash",
						},
					},
				},
			}

			clusterHash, templateHash, err := CalculateHashes(cluster, template)
			Expect(err).NotTo(HaveOccurred())
			Expect(clusterHash).To(Equal("existing-hash"))
			Expect(templateHash).NotTo(BeEmpty())
		})

		It("should handle nil cluster resource", func() {
			template := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Test",
					"spec": map[string]interface{}{
						"field": "value",
					},
				},
			}

			clusterHash, templateHash, err := CalculateHashes(nil, template)
			Expect(err).NotTo(HaveOccurred())
			Expect(clusterHash).To(BeEmpty())
			Expect(templateHash).NotTo(BeEmpty())
		})
	})

	Context("Hash Annotation Functions", func() {
		It("should set hash annotation correctly", func() {
			obj := &unstructured.Unstructured{}
			hash := "test-hash-123"

			SetHashAnnotation(obj, hash)

			annotations := obj.GetAnnotations()
			Expect(annotations).NotTo(BeNil())
			Expect(annotations[resources.HashedData]).To(Equal(hash))
		})

		It("should update existing annotations", func() {
			obj := &unstructured.Unstructured{}
			obj.SetAnnotations(map[string]string{
				"existing": "annotation",
			})

			hash := "new-hash"
			SetHashAnnotation(obj, hash)

			annotations := obj.GetAnnotations()
			Expect(annotations["existing"]).To(Equal("annotation"))
			Expect(annotations[resources.HashedData]).To(Equal(hash))
		})
	})

	Context("Resource Merging Functions", func() {
		It("should merge resources correctly", func() {
			cluster := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Test",
					"spec": map[string]interface{}{
						"field1": "cluster-value",
						"field2": "cluster-only",
					},
				},
			}

			template := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Test",
					"spec": map[string]interface{}{
						"field1": "template-value",
						"field3": "template-only",
					},
				},
			}

			merged, err := MergeResources(cluster, template)
			Expect(err).NotTo(HaveOccurred())
			Expect(merged).NotTo(BeNil())
		})

		It("should handle marshal errors gracefully", func() {
			// Create an object that will cause marshal errors
			cluster := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"invalid": make(chan int), // channels cannot be marshaled
				},
			}

			template := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Test",
				},
			}

			_, err := MergeResources(cluster, template)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("CR Merging Functions", func() {
		It("should merge CRs correctly", func() {
			defaultCR := []byte(`{"spec": {"field1": "default", "field2": "default-only"}}`)
			changedCR := []byte(`{"spec": {"field1": "changed", "field3": "changed-only"}}`)

			result := MergeCR(defaultCR, changedCR)
			Expect(result).NotTo(BeNil())
			Expect(result).To(HaveKey("spec"))
		})

		It("should handle empty CRs", func() {
			result := MergeCR([]byte{}, []byte{})
			Expect(result).NotTo(BeNil())
			Expect(result).To(BeEmpty())
		})

		It("should handle only default CR", func() {
			defaultCR := []byte(`{"spec": {"field": "value"}}`)
			result := MergeCR(defaultCR, []byte{})
			Expect(result).To(HaveKey("spec"))
		})

		It("should handle only changed CR", func() {
			changedCR := []byte(`{"spec": {"field": "value"}}`)
			result := MergeCR([]byte{}, changedCR)
			Expect(result).To(HaveKey("spec"))
		})

		It("should handle invalid JSON gracefully", func() {
			defaultCR := []byte(`invalid json`)
			changedCR := []byte(`{"spec": {"field": "value"}}`)
			result := MergeCR(defaultCR, changedCR)
			// Should not panic and return something
			Expect(result).NotTo(BeNil())
		})
	})
})

var _ = Describe("Resource Status Functions", func() {
	var (
		testNamespace = "test-namespace"
		fakeClient    client.Client
	)

	BeforeEach(func() {
		fakeClient = fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
	})

	Context("Redis Resource Status", func() {
		It("should return not found when Redis CR doesn't exist", func() {
			status, ready := GetRedisResourceStatus(ctx, fakeClient, testNamespace)

			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotFound))
			Expect(status.ObjectName).To(Equal(resources.Rediscp))
			Expect(status.Kind).To(Equal(resources.RedisKind))
		})

		It("should return completed when Redis CR is ready", func() {
			redisCR := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": resources.RedisAPIGroup + "/" + resources.Version,
					"kind":       resources.RedisKind,
					"metadata": map[string]interface{}{
						"name":      resources.Rediscp,
						"namespace": testNamespace,
					},
					"status": map[string]interface{}{
						resources.RedisStatus: resources.StatusCompleted,
					},
				},
			}
			redisCR.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   resources.RedisAPIGroup,
				Version: resources.Version,
				Kind:    resources.RedisKind,
			})

			Expect(fakeClient.Create(ctx, redisCR)).To(Succeed())

			status, ready := GetRedisResourceStatus(ctx, fakeClient, testNamespace)
			Expect(ready).To(BeTrue())
			Expect(status.Status).To(Equal(resources.StatusCompleted))
		})

		It("should return not ready when Redis CR exists but not completed", func() {
			redisCR := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": resources.RedisAPIGroup + "/" + resources.Version,
					"kind":       resources.RedisKind,
					"metadata": map[string]interface{}{
						"name":      resources.Rediscp,
						"namespace": testNamespace,
					},
					"status": map[string]interface{}{
						resources.RedisStatus: "Pending",
					},
				},
			}
			redisCR.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   resources.RedisAPIGroup,
				Version: resources.Version,
				Kind:    resources.RedisKind,
			})

			Expect(fakeClient.Create(ctx, redisCR)).To(Succeed())

			status, ready := GetRedisResourceStatus(ctx, fakeClient, testNamespace)
			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotReady))
		})

		It("should handle Redis CR with partial status", func() {
			redisCR := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": resources.RedisAPIGroup + "/" + resources.Version,
					"kind":       resources.RedisKind,
					"metadata": map[string]interface{}{
						"name":      resources.Rediscp,
						"namespace": testNamespace,
					},
					"status": map[string]interface{}{
						"phase": "Initializing",
					},
				},
			}
			redisCR.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   resources.RedisAPIGroup,
				Version: resources.Version,
				Kind:    resources.RedisKind,
			})

			Expect(fakeClient.Create(ctx, redisCR)).To(Succeed())

			status, ready := GetRedisResourceStatus(ctx, fakeClient, testNamespace)
			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusError))
		})

		It("should handle Redis CR with empty status", func() {
			redisCR := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": resources.RedisAPIGroup + "/" + resources.Version,
					"kind":       resources.RedisKind,
					"metadata": map[string]interface{}{
						"name":      resources.Rediscp,
						"namespace": testNamespace,
					},
				},
			}
			redisCR.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   resources.RedisAPIGroup,
				Version: resources.Version,
				Kind:    resources.RedisKind,
			})

			Expect(fakeClient.Create(ctx, redisCR)).To(Succeed())

			status, ready := GetRedisResourceStatus(ctx, fakeClient, testNamespace)
			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusError))
		})
	})

	Context("OperandRequest Status", func() {
		It("should return not found when OperandRequest doesn't exist", func() {
			status, ready := GetOperandRequestStatus(ctx, fakeClient, testNamespace)

			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotFound))
			Expect(status.ObjectName).To(Equal(resources.UserMgmtOpreq))
		})

		It("should return running when OperandRequest is running", func() {
			operandReq := &odlm.OperandRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resources.UserMgmtOpreq,
					Namespace: testNamespace,
				},
				Status: odlm.OperandRequestStatus{
					Phase: resources.PhaseRunning,
				},
			}

			Expect(fakeClient.Create(ctx, operandReq)).To(Succeed())

			status, ready := GetOperandRequestStatus(ctx, fakeClient, testNamespace)
			Expect(ready).To(BeTrue())
			Expect(status.Status).To(Equal(resources.PhaseRunning))
		})

		It("should handle OperandRequest with different phases", func() {
			phases := []string{"Creating", "Running", "Succeeded", "Failed", "Pending"}

			for _, phase := range phases {
				// Delete any existing OperandRequest with the same name
				existingReq := &odlm.OperandRequest{}
				if err := fakeClient.Get(ctx, client.ObjectKey{Name: resources.UserMgmtOpreq, Namespace: testNamespace}, existingReq); err == nil {
					Expect(fakeClient.Delete(ctx, existingReq)).To(Succeed())
				}

				operandReq := &odlm.OperandRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resources.UserMgmtOpreq, // Use the correct name that the function looks for
						Namespace: testNamespace,
					},
					Status: odlm.OperandRequestStatus{
						Phase: odlm.ClusterPhase(phase),
					},
				}

				Expect(fakeClient.Create(ctx, operandReq)).To(Succeed())

				status, ready := GetOperandRequestStatus(ctx, fakeClient, testNamespace)
				Expect(status).NotTo(BeNil())
				if phase == "Running" {
					Expect(ready).To(BeTrue())
				} else {
					Expect(ready).To(BeFalse())
				}
			}
		})
	})

	Context("Job Status", func() {
		It("should return not found when Job doesn't exist", func() {
			status, ready := GetJobStatus(ctx, fakeClient, "test-job", testNamespace)

			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotFound))
			Expect(status.ObjectName).To(Equal("test-job"))
		})

		It("should return completed when Job is successful", func() {
			job := &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-job",
					Namespace: testNamespace,
				},
				Status: batchv1.JobStatus{
					Conditions: []batchv1.JobCondition{
						{
							Type:   batchv1.JobComplete,
							Status: corev1.ConditionTrue,
						},
					},
				},
			}

			Expect(fakeClient.Create(ctx, job)).To(Succeed())

			status, ready := GetJobStatus(ctx, fakeClient, "test-job", testNamespace)
			Expect(ready).To(BeTrue())
			Expect(status.Status).To(Equal(resources.StatusCompleted))
		})

		It("should return failed when Job has failed", func() {
			job := &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-job",
					Namespace: testNamespace,
				},
				Status: batchv1.JobStatus{
					Conditions: []batchv1.JobCondition{
						{
							Type:   batchv1.JobFailed,
							Status: corev1.ConditionTrue,
						},
					},
				},
			}

			Expect(fakeClient.Create(ctx, job)).To(Succeed())

			status, ready := GetJobStatus(ctx, fakeClient, "test-job", testNamespace)
			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusFailed))
		})

		It("should return running when Job is in progress", func() {
			job := &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-job",
					Namespace: testNamespace,
				},
				Status: batchv1.JobStatus{
					Conditions: []batchv1.JobCondition{}, // No completion conditions
				},
			}

			Expect(fakeClient.Create(ctx, job)).To(Succeed())

			status, ready := GetJobStatus(ctx, fakeClient, "test-job", testNamespace)
			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.PhaseRunning))
		})
	})

	Context("Service Status", func() {
		It("should return not found when Service doesn't exist", func() {
			status, ready := GetServiceStatus(ctx, fakeClient, "test-service", testNamespace)

			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotFound))
		})

		It("should return completed when Service has ClusterIP", func() {
			service := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: testNamespace,
				},
				Spec: corev1.ServiceSpec{
					ClusterIP: "10.0.0.1",
					Type:      "ClusterIP",
				},
			}

			Expect(fakeClient.Create(ctx, service)).To(Succeed())

			status, ready := GetServiceStatus(ctx, fakeClient, "test-service", testNamespace)
			Expect(ready).To(BeTrue())
			Expect(status.Status).To(Equal(resources.StatusCompleted))
		})

		It("should return completed for headless service", func() {
			service := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: testNamespace,
				},
				Spec: corev1.ServiceSpec{
					ClusterIP: "None",
					Type:      "ClusterIP",
				},
			}

			Expect(fakeClient.Create(ctx, service)).To(Succeed())

			status, ready := GetServiceStatus(ctx, fakeClient, "test-service", testNamespace)
			Expect(ready).To(BeTrue())
			Expect(status.Status).To(Equal(resources.StatusCompleted))
		})

		It("should return not ready when Service has no ClusterIP", func() {
			service := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: testNamespace,
				},
				Spec: corev1.ServiceSpec{
					ClusterIP: "",
					Type:      "ClusterIP",
				},
			}

			Expect(fakeClient.Create(ctx, service)).To(Succeed())

			status, ready := GetServiceStatus(ctx, fakeClient, "test-service", testNamespace)
			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotReady))
		})
	})

	Context("Secret Status", func() {
		It("should return not found when Secret doesn't exist", func() {
			status, ready := GetSecretStatus(ctx, fakeClient, "test-secret", testNamespace)

			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotFound))
		})

		It("should return completed when Secret exists", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: testNamespace,
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			}

			Expect(fakeClient.Create(ctx, secret)).To(Succeed())

			status, ready := GetSecretStatus(ctx, fakeClient, "test-secret", testNamespace)
			Expect(ready).To(BeTrue())
			Expect(status.Status).To(Equal(resources.StatusCompleted))
		})
	})

	Context("Route Status", func() {
		It("should return not found when Route doesn't exist", func() {
			status, ready := GetRouteStatus(ctx, fakeClient, "test-route", testNamespace)

			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotFound))
		})

		It("should return completed when Route is admitted", func() {
			route := &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: testNamespace,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   routev1.RouteAdmitted,
									Status: corev1.ConditionTrue,
								},
							},
						},
					},
				},
			}

			Expect(fakeClient.Create(ctx, route)).To(Succeed())

			status, ready := GetRouteStatus(ctx, fakeClient, "test-route", testNamespace)
			Expect(ready).To(BeTrue())
			Expect(status.Status).To(Equal(resources.StatusCompleted))
		})

		It("should return not ready when Route has no ingress", func() {
			route := &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: testNamespace,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{}, // Empty ingress
				},
			}

			Expect(fakeClient.Create(ctx, route)).To(Succeed())

			status, ready := GetRouteStatus(ctx, fakeClient, "test-route", testNamespace)
			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotReady))
		})

		It("should return not ready when Route is not admitted", func() {
			route := &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: testNamespace,
				},
				Status: routev1.RouteStatus{
					Ingress: []routev1.RouteIngress{
						{
							Conditions: []routev1.RouteIngressCondition{
								{
									Type:   routev1.RouteAdmitted,
									Status: corev1.ConditionFalse,
								},
							},
						},
					},
				},
			}

			Expect(fakeClient.Create(ctx, route)).To(Succeed())

			status, ready := GetRouteStatus(ctx, fakeClient, "test-route", testNamespace)
			Expect(ready).To(BeFalse())
			Expect(status.Status).To(Equal(resources.StatusNotReady))
		})
	})
})

var _ = Describe("Secret Data Functions", func() {
	var (
		testNamespace = "test-namespace"
		fakeClient    client.Client
	)

	BeforeEach(func() {
		fakeClient = fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
	})

	Context("GetSecretData", func() {
		It("should retrieve secret data correctly", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: testNamespace,
				},
				Data: map[string][]byte{
					"username": []byte("testuser"),
					"password": []byte("testpass"),
				},
			}

			Expect(fakeClient.Create(ctx, secret)).To(Succeed())

			username, err := GetSecretData(ctx, fakeClient, "test-secret", testNamespace, "username")
			Expect(err).NotTo(HaveOccurred())
			Expect(username).To(Equal("testuser"))

			password, err := GetSecretData(ctx, fakeClient, "test-secret", testNamespace, "password")
			Expect(err).NotTo(HaveOccurred())
			Expect(password).To(Equal("testpass"))
		})

		It("should return error when secret doesn't exist", func() {
			_, err := GetSecretData(ctx, fakeClient, "nonexistent-secret", testNamespace, "key")
			Expect(err).To(HaveOccurred())
		})

		It("should return error when key doesn't exist in secret", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: testNamespace,
				},
				Data: map[string][]byte{
					"existing-key": []byte("value"),
				},
			}

			Expect(fakeClient.Create(ctx, secret)).To(Succeed())

			_, err := GetSecretData(ctx, fakeClient, "test-secret", testNamespace, "nonexistent-key")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("key nonexistent-key not found"))
		})
	})
})

var _ = Describe("Route Functions", func() {
	var (
		testNamespace = "test-namespace"
		fakeClient    client.Client
	)

	BeforeEach(func() {
		fakeClient = fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
	})

	Context("GetHost", func() {
		It("should get route host correctly", func() {
			route := &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-route",
					Namespace: testNamespace,
				},
				Spec: routev1.RouteSpec{
					Host: "test.example.com",
				},
			}

			Expect(fakeClient.Create(ctx, route)).To(Succeed())

			host, err := GetHost(ctx, fakeClient, "test-route", testNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(host).To(Equal("test.example.com"))
		})

		It("should return error when route doesn't exist", func() {
			_, err := GetHost(ctx, fakeClient, "nonexistent-route", testNamespace)
			Expect(err).To(HaveOccurred())
		})
	})
})

var _ = Describe("Wait Functions", func() {
	var (
		testNamespace = "test-namespace"
		fakeClient    client.Client
		testTimeout   = 100 * time.Millisecond
	)

	BeforeEach(func() {
		fakeClient = fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
	})

	Context("WaitForJob", func() {
		It("should timeout when job doesn't exist", func() {
			ctxWithTimeout, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()

			err := WaitForJob(ctxWithTimeout, fakeClient, testNamespace, "nonexistent-job")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("WaitForOperatorReady", func() {
		It("should timeout when OperandRequest is not ready", func() {
			operandReq := &odlm.OperandRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-operand",
					Namespace: testNamespace,
				},
				Status: odlm.OperandRequestStatus{
					Phase: "Pending",
				},
			}

			Expect(fakeClient.Create(ctx, operandReq)).To(Succeed())

			ctxWithTimeout, cancel := context.WithTimeout(ctx, testTimeout)
			defer cancel()

			err := WaitForOperatorReady(ctxWithTimeout, fakeClient, "test-operand", testNamespace)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("WaitForDeploymentReady", func() {
		It("should timeout when deployment is not ready", func() {
			replicas := int32(2)
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-deployment",
					Namespace: testNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: &replicas,
				},
				Status: appsv1.DeploymentStatus{
					ReadyReplicas: 1, // Less than desired
				},
			}

			Expect(fakeClient.Create(ctx, deployment)).To(Succeed())

			ctxWithTimeout, cancel := context.WithTimeout(ctx, testTimeout)
			defer cancel()

			err := WaitForDeploymentReady(ctxWithTimeout, fakeClient, testNamespace, "test")
			Expect(err).To(HaveOccurred())
		})
	})
})
