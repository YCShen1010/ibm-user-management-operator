package yamls

var IM_INTEGRATION_YAMLS = []string{
	IM_INTEGRATION_SECRET,
}

var IM_INTEGRATION_SECRET = `
kind: Secret
apiVersion: v1
metadata:
  name: mcsp-im-integration-details
stringData:
  ACCOUNT_IAM_CONSOLE_URL: {{ .AccountIAMConsoleURL }}
  ACCOUNT_IAM_URL: {{ .AccountIAMURL }}
  ACCOUNT_NAME: {{ .AccountName }}
  SERVICEID_NAME: {{ .ServiceIDName }}
  SERVICE_NAME: {{ .ServiceName }}
  SUBSCRIPTION_NAME: {{ .SubscriptionName }}
  APIKEY_NAME: default-apikey
type: Opaque
`
