package yamls

var StaticYamlsUI = []string{
	UI_ISSUER_CA,
	UI_CA_CERT,
	SvcAPI,
	SvcInstance,
	DeploymentAPI,
	DeploymentInstance,
}

var TemplateYamlsUI = []string{
	UI_SVC_CERT,
	ConfigUI,
	SecretUI,
	RouteInstance,
	RouteAPIInstance,
}

var UI_ISSUER_CA = `
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: account-iam-ui-ca-issuer
spec:
  ca:
    secretName: cs-ca-certificate-secret
`

var UI_CA_CERT = `
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: account-iam-ui-ca-cert
spec:
  isCA: true
  commonName: account-iam-ui-ca-cert
  secretName: account-iam-ui-ca-cert
  duration: 87660h0m0s
  renewBefore: 85500h0m0s
  issuerRef:
    name: account-iam-ui-ca-issuer
    kind: Issuer
    group: cert-manager.io
`

var UI_SVC_CERT = `
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: account-iam-ui-svc-tls-cert
spec:
  secretName: account-iam-ui-svc-tls-cert
  dnsNames:
    - {{ .Hostname }}
  issuerRef:
    name: account-iam-ui-ca-issuer
    kind: Issuer
    group: cert-manager.io
`

var SvcAPI = `
########################################################
# IBM Confidential
# Copyright IBM Corporation 2024
########################################################

apiVersion: v1
kind: Service
metadata:
  labels:
    app: 'account-iam-ui-api-service-onprem'
  name: 'account-iam-ui-api-service-onprem'
  annotations:
    service.beta.openshift.io/serving-cert-secret-name: 'account-iam-ui-api-server-onprem-tls'
spec:
  ports:
    - name: https
      port: 3000
      protocol: TCP
      targetPort: 3000
  selector:
    app: "account-iam-ui-api-service-onprem-api"
`
var SvcInstance = `
########################################################
# IBM Confidential
# Copyright IBM Corporation 2024
########################################################

apiVersion: v1
kind: Service
metadata:
  labels:
    app: 'account-iam-ui-instance-service-onprem'
  name: 'account-iam-ui-instance-service-onprem'
  annotations:
    service.beta.openshift.io/serving-cert-secret-name: 'account-iam-ui-instance-server-onprem-tls'
spec:
  ports:
    - name: https
      port: 3005
      protocol: TCP
      targetPort: 3005
  selector:
    app: 'account-iam-ui-instance-service-onprem-instance'
`

var ConfigUI = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: 'account-iam-ui-config-onprem'
data:
  IAM_API: '{{ .IAMAPI }}'
  NODE_ENV: '{{ .NodeEnv }}'
  HOSTNAME: '{{ .Hostname }}'
  CERT_DIR: '{{ .CertDir }}'
  CONFIG_ENV: '{{ .ConfigEnv }}'
  REDIS_HOST: '{{ .RedisHost }}'
  ACCOUNT_API: '{{ .AccountAPI }}'
  PRODUCT_API: '{{ .ProductAPI }}'
  DEPLOYMENT_ENV: '{{ .ConfigEnv }}'
  METERING_API: '{{ .MeteringAPI }}'
  INSTANCE_API: '{{ .InstanceAPI }}'
  ISSUER_BASE_URL: '{{ .IssuerBaseURL }}'
  SUBSCRIPTION_API: '{{ .SubscriptionAPI }}'
  API_OAUTH_TOKEN_URL: '{{ .APIOAUTHTokenURL }}'
  LANDING_PAGE_URL: 'https://{{ .Hostname }}/landing'
  LOGIN_PAGE_URL: 'https://{{ .Hostname }}/auth/login'
  CALLBACK_URL: 'https://{{ .Hostname }}/auth/login/callback'
  APOLLO_CLIENT_API_URL: 'https://{{ .Hostname }}/api/graphql'
`

var SecretUI = `
apiVersion: v1
kind: Secret
metadata:
  name: 'account-iam-ui-secrets-onprem'
stringData:
  .env: |-
    REDIS_CA={{ .RedisCA }}
    CLIENT_ID={{ .ClientID }}
    CLIENT_SECRET={{ .ClientSecret }}
    DISABLE_REDIS={{ .DisableRedis }}
    SESSION_SECRET={{ .SessionSecret }}
    DEPLOYMENT_CLOUD={{ .DeploymentCloud }}
    IAM_GLOBAL_APIKEY={{ .IAMGlobalAPIKey }}
    API_OAUTH_CLIENT_ID={{ .APIOAUTHClientID }}
    API_OAUTH_CLIENT_SECRET={{ .APIOAUTHClientSecret }}

    IAM_API={{ .IAMAPI }}
    SUBSCRIPTION_FILTER_START=2024-05-30

    MY_IBM_URL={{ .MyIBMURL }}
    BASE_URL=https://{{ .Hostname }}
    LANDING_PAGE_URL=https://{{ .Hostname }}/landing
    AWS_PROVISIONING_URL={{ .AWSProvisioningURL }}
    LOGIN_PAGE_URL=https://{{ .Hostname }}/auth/login
    APOLLO_CLIENT_API_URL=https://{{ .Hostname }}/api/graphql
    ACCOUNT_PAGE_URL=https://{{ .Hostname }}/account/dashboard
    IBM_CLOUD_PROVISIONING_URL={{ .IBMCloudProvisioningURL }}

    PRODUCT_REGISTRATION_USERNAME={{ .ProductRegistrationUsername }}
    PRODUCT_REGISTRATION_PASSWORD={{ .ProductRegistrationPassword }}
    NODE_TLS_REJECT_UNAUTHORIZED=0

    USAGE_SUPPORT_PRODUCT_IDS=["prod-ld7uduo5mrhuq", "waaj123e-13ee-4808-8b9c-612698bc4754", "prod-jtuzrfuxofhqq", "waaj123e-13ee-4808-8b9c-612698bc4754", ]

    # Instance management UI configs
    INSTANCE_MANAGEMENT_LOGIN_ROUTE=/instance/auth/login
    INSTANCE_MANAGEMENT_LOGIN_CALLBACK_ROUTE=/instance/auth/login/callback
    INSTANCE_MANAGEMENT_BASE_URL=https://{{ .InstanceManagementHostname }}
    APOLLO_CLIENT_INSTANCE_API_URL=https://{{ .InstanceManagementHostname }}/api/graphql/instance
    IM_ID_MGMT={{ .IMIDMgmt}}
    ONPREM_ACCOUNT={{ .OnPremAccount }}
    ONPREM_INSTANCE={{ .OnPremInstance }}
    CS_IDP_URL={{ .CSIDPURL }}
`

var RouteInstance = `
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: 'account-iam-ui-instance-onprem'
  annotations:
    haproxy.router.openshift.io/timeout: 30m
spec:
  host: {{ .InstanceManagementHostname }}
  to:
    kind: Service
    name: 'account-iam-ui-instance-service-onprem'
    weight: 100
  port:
    targetPort: https
  tls:
    termination: reencrypt
    insecureEdgeTerminationPolicy: Redirect
  path: /instance
  wildcardPolicy: None
`

var RouteAPIInstance = `
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: 'account-iam-ui-api-instance-onprem'
  annotations:
    haproxy.router.openshift.io/timeout: 30m
spec:
  host: {{ .InstanceManagementHostname }}
  to:
    kind: Service
    name: 'account-iam-ui-api-service-onprem'
    weight: 100
  port:
    targetPort: https
  tls:
    termination: reencrypt
    insecureEdgeTerminationPolicy: Redirect
  path: /api/graphql/instance
  wildcardPolicy: None
`

var DeploymentAPI = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: 'account-iam-ui-api-deployment-onprem'
  labels:
    app: account-iam-ui-api-service-onprem
spec:
  selector:
    matchLabels:
      app: 'account-iam-ui-api-service-onprem-api'
  replicas: 1
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 35%
  template:
    metadata:
      labels:
        app: 'account-iam-ui-api-service-onprem-api'
        version: 1.2.0
    spec:
      containers:
        - name: 'account-iam-ui-api-service-onprem-api'
          image: RELATED_IMAGE_API_SERVICE
          imagePullPolicy: Always
          ports:
            - containerPort: 3000
          env:
            - name: DEPLOYMENT_ENV
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: DEPLOYMENT_ENV
            - name: HOSTNAME
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: HOSTNAME
            - name: METERING_API
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: METERING_API
            - name: IAM_API
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: IAM_API
            - name: PRODUCT_API
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: PRODUCT_API
            - name: SUBSCRIPTION_API
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: SUBSCRIPTION_API
            - name: INSTANCE_API
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: INSTANCE_API
            - name: ACCOUNT_API
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: ACCOUNT_API
            - name: API_OAUTH_TOKEN_URL
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: API_OAUTH_TOKEN_URL
            - name: CERT_DIR
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: CERT_DIR
            - name: ISSUER_BASE_URL
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: ISSUER_BASE_URL
            - name: APOLLO_CLIENT_API_URL
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: APOLLO_CLIENT_API_URL
            - name: REDIS_HOST
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: REDIS_HOST
          volumeMounts:
            - name: 'account-iam-ui-secrets-onprem'
              mountPath: /opt/app-root/src/apps/api/.env
              readOnly: true
              subPath: .env
            - name: 'account-iam-ui-api-server-onprem-tls'
              mountPath: /opt/app-root/src/security
              readOnly: true
            - name: mutual-tls-auth
              mountPath: /opt/app-root/src/security/mutual-tls-auth
              readOnly: true
            - name: tls
              mountPath: /mnt/tls
              readOnly: true
          resources:
            requests:
              cpu: 200m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          securityContext:
            seccompProfile:
              type: RuntimeDefault
            allowPrivilegeEscalation: false
            privileged: false
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          livenessProbe:
            httpGet:
              port: 3000
              scheme: HTTPS
              path: /healthz/liveness
            periodSeconds: 10
            failureThreshold: 3
          readinessProbe:
            httpGet:
              port: 3000
              scheme: HTTPS
              path: /healthz/readiness
            periodSeconds: 10
            failureThreshold: 3
      terminationGracePeriodSeconds: 10
      volumes:
        - name: 'account-iam-ui-secrets-onprem'
          secret:
            secretName: 'account-iam-ui-secrets-onprem'
        - name: 'account-iam-ui-api-server-onprem-tls'
          secret:
            secretName: 'account-iam-ui-api-server-onprem-tls'
        - name: tls
          configMap:
            name: openshift-service-ca.crt
            items:
              - key: 'service-ca.crt'
                path: ca.crt
        - name: mutual-tls-auth
          projected:
            sources:
              - secret:
                  name:  'account-iam-ui-svc-tls-cert'
                  items:
                    - key: ca.crt
                      path: ca.crt
                    - key: tls.crt
                      path: tls.crt
                    - key: tls.key
                      path: tls.key
      serviceAccountName: user-mgmt-operand-serviceaccount
`

var DeploymentInstance = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: 'account-iam-ui-instance-deployment-onprem'
  labels:
    app: account-iam-ui-instance-service-onprem
spec:
  selector:
    matchLabels:
      app: 'account-iam-ui-instance-service-onprem-instance'
  replicas: 1
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 35%
  template:
    metadata:
      labels:
        app: 'account-iam-ui-instance-service-onprem-instance'
        version: 1.2.0
    spec:
      containers:
        - name: 'account-iam-ui-instance-service-onprem-instance'
          image: RELATED_IMAGE_INSTANCE_MANAGEMENT_SERVICE
          imagePullPolicy: Always
          ports:
            - containerPort: 3005
          env:
            - name: DEPLOYMENT_ENV
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: DEPLOYMENT_ENV
            - name: CALLBACK_URL
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: CALLBACK_URL
            - name: API_OAUTH_TOKEN_URL
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: API_OAUTH_TOKEN_URL
            - name: CERT_DIR
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: CERT_DIR
            - name: ISSUER_BASE_URL
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: ISSUER_BASE_URL
            - name: APOLLO_CLIENT_API_URL
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: APOLLO_CLIENT_API_URL
            - name: REDIS_HOST
              valueFrom:
                configMapKeyRef:
                  name: 'account-iam-ui-config-onprem'
                  key: REDIS_HOST
          volumeMounts:
            - name: 'account-iam-ui-secrets-onprem'
              mountPath: /opt/app-root/src/apps/instance/.env
              readOnly: true
              subPath: .env
            - name: 'account-iam-ui-instance-server-onprem-tls'
              mountPath: /opt/app-root/src/security
              readOnly: true
            - name: tls
              mountPath: /mnt/tls
              readOnly: true
          resources:
            requests:
              cpu: 200m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          securityContext:
            seccompProfile:
              type: RuntimeDefault
            allowPrivilegeEscalation: false
            privileged: false
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          livenessProbe:
            httpGet:
              port: 3005
              scheme: HTTPS
              path: /healthz/liveness
            periodSeconds: 10
            failureThreshold: 3
          readinessProbe:
            httpGet:
              port: 3005
              scheme: HTTPS
              path: /healthz/readiness
            periodSeconds: 10
            failureThreshold: 3
      terminationGracePeriodSeconds: 10
      volumes:
        - name: 'account-iam-ui-secrets-onprem'
          secret:
            secretName: 'account-iam-ui-secrets-onprem'
        - name: 'account-iam-ui-instance-server-onprem-tls'
          secret:
            secretName: 'account-iam-ui-instance-server-onprem-tls'
        - name: tls
          configMap:
            name: openshift-service-ca.crt
            items:
              - key: 'service-ca.crt'
                path: ca.crt
      serviceAccountName: user-mgmt-operand-serviceaccount
`
