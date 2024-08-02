package yamls

const RedisCRTemplate = `
apiVersion: redis.ibm.com/v1
kind: Rediscp
metadata:
  name: account-iam-ui-redis
spec:
  size: {{.RedisCRSize}}
  license:
     accept: true
  cert_name: account-iam-ui-redis-cert
  shutdown: false
  scale_config: medium
  version: {{.RedisCRVersion}}
`
