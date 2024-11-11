package yamls

var ACCOUNT_IAM_RES = []string{
	ACCOUNT_IAM_CA_ISSUER,
	ACCOUNT_IAM_CA_CERT,
	ACCOUNT_IAM_SVC_CERT,
	ACCOUNT_IAM_SERVICE_ACCOUNT,
	ACCOUNT_IAM_SERVICE,
	ACCOUNT_IAM_DEPLOYMENT,
}

var ACCOUNT_IAM_ROUTE_RES = []string{
	ACCOUNT_IAM_ROUTE,
}

var ACCOUNT_IAM_CA_ISSUER = `
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: account-iam-ca-issuer
spec:
  ca:
    secretName: cs-ca-certificate-secret
`

var ACCOUNT_IAM_CA_CERT = `
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: account-iam-ca-cert
spec:
  isCA: true
  commonName: account-iam-ca-cert
  secretName: account-iam-ca-cert
  duration: 8766h0m0s
  issuerRef:
    name: account-iam-ca-issuer
    kind: Issuer
    group: cert-manager.io
`

var ACCOUNT_IAM_SVC_CERT = `
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: account-iam-svc-tls-cert
spec:
  commonName: account-iam.${NAMESPACE}.svc
  secretName: account-iam-svc-tls-cert
  dnsNames:
    - account-iam.${NAMESPACE}.svc
    - account-iam.${NAMESPACE}.svc.cluster.local
  duration: 2160h0m0s
  issuerRef:
    name: account-iam-ca-issuer
    kind: Issuer
    group: cert-manager.io
`

var ACCOUNT_IAM_SERVICE_ACCOUNT = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: account-iam
  labels:
    app.kubernetes.io/component: backend
    app.kubernetes.io/instance: account-iam
    app.kubernetes.io/name: account-iam
    app.kubernetes.io/part-of: account-iam
    bcdr-candidate: t
    component-name: iam-services
    for-product: all
    name: account-iam
`

var ACCOUNT_IAM_SERVICE = `
apiVersion: v1
kind: Service
metadata:
  name: account-iam
  annotations:
    service.kubernetes.io/topology-aware-hints: Auto
    service.kubernetes.io/topology-mode: Auto
  labels:
    app.kubernetes.io/component: backend
    app.kubernetes.io/instance: account-iam
    app.kubernetes.io/name: account-iam
    app.kubernetes.io/part-of: account-iam
    bcdr-candidate: t
    component-name: iam-services
    for-product: all
spec:
  ports:
  - name: 9445-tcp
    port: 9445
    protocol: TCP
    targetPort: 9445
  selector:
    app.kubernetes.io/instance: account-iam
  sessionAffinity: None
  type: ClusterIP
`

var ACCOUNT_IAM_DEPLOYMENT = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: account-iam
  labels:
    app.kubernetes.io/component: backend
    app.kubernetes.io/instance: account-iam
    app.kubernetes.io/name: account-iam
    app.kubernetes.io/part-of: account-iam
    bcdr-candidate: t
    component-name: iam-services
    for-product: all
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/instance: account-iam
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      labels:
        app.kubernetes.io/component: backend
        app.kubernetes.io/instance: account-iam
        app.kubernetes.io/name: account-iam
        app.kubernetes.io/part-of: account-iam
        bcdr-candidate: t
        component-name: iam-services
        for-product: all
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 50
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app.kubernetes.io/instance: account-iam
              topologyKey: topology.kubernetes.io/zone
          - weight: 50
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app.kubernetes.io/instance: account-iam
              topologyKey: kubernetes.io/hostname
      containers:
      - name: app
        image: RELATED_IMAGE_ACCOUNT_IAM
        imagePullPolicy: Always
        env:
        - name: cert_defaultKeyStore
          value: /var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt
        - name: TLS_DIR
          value: /etc/x509/certs
        - name: SA_RESOURCE_VERSION
          value: "230752380"
        - name: WLP_LOGGING_CONSOLE_LOGLEVEL
          value: info
        - name: WLP_LOGGING_CONSOLE_SOURCE
          value: message,accessLog,ffdc,audit
        - name: WLP_LOGGING_CONSOLE_FORMAT
          value: json
        - name: SEC_IMPORT_K8S_CERTS
          value: "true"
        - name: SERVICE_CERT_SECRET_RESOURCE_VERSION
          value: "230832362"
        envFrom:
        - configMapRef:
            name: account-iam-env-configmap-development
        ports:
        - containerPort: 9445
          name: 9445-tcp
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /api/2.0/health/liveness
            port: 9445
            scheme: HTTPS
          timeoutSeconds: 5
          periodSeconds: 10
          successThreshold: 1
          failureThreshold: 5
        readinessProbe:
          httpGet:
            path: /api/2.0/health/readiness
            port: 9445
            scheme: HTTPS
          timeoutSeconds: 5
          periodSeconds: 10
          successThreshold: 1
          failureThreshold: 3
        startupProbe:
          httpGet:
            path: /api/2.0/health/started
            port: 9445
            scheme: HTTPS
          timeoutSeconds: 5
          periodSeconds: 10
          successThreshold: 1
          failureThreshold: 60
        resources:
          limits:
            cpu: 1500m
            memory: 800Mi
          requests:
            cpu: 300m
            memory: 400Mi
        securityContext:
          capabilities:
            drop:
              - ALL
          privileged: false
          runAsNonRoot: true
          readOnlyRootFilesystem: false
          allowPrivilegeEscalation: false
          seccompProfile:
            type: RuntimeDefault
        volumeMounts:
        - mountPath: /var/run/secrets/tokens
          name: account-iam-token
        - mountPath: /config/variables/oidc
          name: account-iam-oidc
          readOnly: true
        - mountPath: /config/variables/okd
          name: account-iam-okd
          readOnly: true
        - mountPath: /config/variables
          name: account-iam-variables
          readOnly: true
        - mountPath: /etc/x509/certs
          name: svc-certificate
          readOnly: true
      serviceAccountName: account-iam
      topologySpreadConstraints:
      - maxSkew: 1
        topologyKey: topology.kubernetes.io/zone
        whenUnsatisfiable: ScheduleAnyway
        labelSelector:
          matchLabels:
            app.kubernetes.io/instance: account-iam
      - maxSkew: 1
        topologyKey: kubernetes.io/hostname
        whenUnsatisfiable: ScheduleAnyway
        labelSelector:
          matchLabels:
            app.kubernetes.io/instance: account-iam
      volumes:
      - name: account-iam-token
        projected:
          sources:
          - serviceAccountToken:
              audience: openshift
              path: account-iam-token
      - name: account-iam-oidc
        secret:
          secretName: account-iam-oidc-client-auth
      - name: account-iam-okd
        secret:
          secretName: account-iam-okd-auth
      - name: account-iam-variables
        projected:
          sources:
          - secret:
              name: account-iam-database-secret
          - secret:
              name: account-iam-mpconfig-secrets
      - name: svc-certificate
        secret:
          secretName: account-iam-svc-tls-cert
`

var ACCOUNT_IAM_ROUTE = `
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: account-iam
  annotations:
    openshift.io/host.generated: "true"
  labels:
    app.kubernetes.io/component: backend
    app.kubernetes.io/instance: account-iam
    app.kubernetes.io/name: account-iam
    app.kubernetes.io/part-of: account-iam
    bcdr-candidate: t
    component-name: iam-services
    for-product: all
spec:
  port:
    targetPort: 9445-tcp
  tls:
    termination: reencrypt
    destinationCACertificate: |-
{{ .CAcert }}
  to:
    kind: Service
    name: account-iam
    weight: 100
  wildcardPolicy: None
`
