package yamls

var IMConfigYamls = []string{
	IM_CONFIG_JOB,
}

var IM_CONFIG_JOB = `
apiVersion: batch/v1
kind: Job
metadata:
  name: mcsp-im-config-job
  labels:
    app: mcsp-im-config-job
spec:
  template:
    metadata:
      labels:
        app: mcsp-im-config-job
    spec:
      containers:
      - name: mcsp-im-config-job
        image: RELATED_IMAGE_MCSP_IM_CONFIG_JOB
        command: ["./mcsp-im-config-job"]
        imagePullPolicy: Always
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
          runAsNonRoot: true
          seccompProfile:
            type: RuntimeDefault
        env:
          - name: NAMESPACE
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
          - name: IM_HOST_BASE_URL
            valueFrom:
              configMapKeyRef:
                name: ibm-iam-bindinfo-ibmcloud-cluster-info
                key: cluster_endpoint
          - name: ACCOUNT_IAM_BASE_URL
            valueFrom:
              secretKeyRef:
                name: mcsp-im-integration-details
                key: ACCOUNT_IAM_URL
          - name: ACCOUNT_IAM_CONSOLE_BASE_URL
            valueFrom:
              secretKeyRef:
                name: mcsp-im-integration-details
                key: ACCOUNT_IAM_CONSOLE_URL
          - name: API_KEY_SECRET_NAME
            value: mcsp-im-integration-details
          - name: ACCOUNT_NAME
            valueFrom:
              secretKeyRef:
                name: mcsp-im-integration-details
                key: ACCOUNT_NAME
          - name: SUBSCRIPTION_NAME
            valueFrom:
              secretKeyRef:
                name: mcsp-im-integration-details
                key: SUBSCRIPTION_NAME
          - name: SERVICE_NAME
            valueFrom:
              secretKeyRef:
                name: mcsp-im-integration-details
                key: SERVICE_NAME
          - name: SERVICEID_NAME
            valueFrom:
              secretKeyRef:
                name: mcsp-im-integration-details
                key: SERVICEID_NAME
      serviceAccountName: user-mgmt-operand-serviceaccount
      restartPolicy: OnFailure
`
