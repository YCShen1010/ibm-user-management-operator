package yamls

var OperandRBACs = []string{
	USER_MGMT_OPERAND_SA,
	USER_MGMT_OPERAND_ROLE,
	USER_MGMT_OPERAND_RB,
}

const USER_MGMT_OPERAND_ROLE = `
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: user-mgmt-operand-role
rules:
  - verbs:
      - get
      - list
      - watch
      - create
      - update
      - delete
    apiGroups:
      - ''
    resources:
      - secrets
      - configmaps
      - pods
`

const USER_MGMT_OPERAND_SA = `
kind: ServiceAccount
apiVersion: v1
metadata:
  name: user-mgmt-operand-serviceaccount
  labels:
    app.kubernetes.io/instance: user-mgmt-operand-serviceaccount
`

const USER_MGMT_OPERAND_RB = `
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: user-mgmt-operand-rolebinding
subjects:
  - kind: ServiceAccount
    name: user-mgmt-operand-serviceaccount
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: user-mgmt-operand-role
`
