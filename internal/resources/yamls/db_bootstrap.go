package yamls

const DB_BOOTSTRAP_JOB = `
apiVersion: batch/v1
kind: Job
metadata:
  name: create-account-iam-db
spec:
  template:
    metadata:
      name: create-account-iam-db
    spec:
      containers:
      - name: postgres
        image: RELATED_IMAGE_MCSP_UTILS
        command: ["/bin/bash", "/db-init/create_db.sh"]
        volumeMounts:
        - name: psql-credentials
          mountPath: /psql-credentials
        - name: db-password
          mountPath: /db-password
        - name: data-volume
          mountPath: /data
      restartPolicy: OnFailure
      volumes:
      - name: psql-credentials
        secret:
          secretName: common-service-db-superuser
          items:
          - key: username
            path: username
          - key: password
            path: password
          defaultMode: 420  
      - name: db-password
        secret:
          secretName: user-mgmt-bootstrap
          items:
          - key: PGPassword
            path: password
          defaultMode: 420  
      - name: data-volume
        emptyDir: {}      
  backoffLimit: 4

`
