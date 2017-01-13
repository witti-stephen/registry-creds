# AWS ECR Credentials
Allow for AWS ECR credentials to be refreshed inside your Kubernetes cluster via ImagePullSecrets

## How it works

1. The tool runs as a pod in the `kube-system` namespace.
- It gets credentials from AWS ECR via the aws-go sdk
- Next it creates a secret named `awsecr-creds` (by default)
- Then it sets up this secret to be used in the `ImagePullSecrets` for the default service account
- Whenever a pod is created, this secret is attached to the pod
- The container will refresh the credentials by default every 11 hours 55 minutes since they expire at 12 hours
- Enabled for use with Minikube as an addon (https://github.com/kubernetes/minikube#add-ons)

_NOTE: This will setup credentials across ALL namespaces!_

## Parameters

The following parameters are driven via Environment variables.

- Environment Variables:
  - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY: Credentials to access AWS
  - awsaccount: AWS Account Id 
  - awsregion: (optional) Can override the default aws region by setting this variable. Note: The region can also be specified as an arg to the binary.  

## How to setup running in AWS

1. Clone the repo and navigate to directory

2a. If running on AWS EC2, make sure your EC2 instances have the following IAM permissions:

  ```json
  {
   "Effect": "Allow",
    "Action": [
     "ecr:GetAuthorizationToken",
     "ecr:BatchCheckLayerAvailability",
     "ecr:GetDownloadUrlForLayer",
     "ecr:GetRepositoryPolicy",
     "ecr:DescribeRepositories",
     "ecr:ListImages",
     "ecr:BatchGetImage"
   ],
   "Resource": "*"
  }
  ```

2b. If you are not running in AWS Cloud, then you can still use this tool! Edit & create the sample [secret](k8s/secret.yaml) and update values for AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS Account Id (base64 encoded)

```bash
echo -n "secret-key" | base64

kubectl create -f k8s/secret.yaml
```

3. Create the replication controller. NOTE: If running on prem, no need to provide AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY since that will come from the EC2 instance.

  ```bash
  kubectl create -f k8s/replicationController.yml
  ```

## How to setup running in GCR

1. Clone the repo and navigate to directory

2. Input your application_default_credentials.json information into a secret with the template at k8s/gcr-secret.yaml:
```bash
apiVersion: v1
data:
  application_default_credentials.json: <base-64 encoded ~/.config/gcloud/application_default_credentials.json>
kind: Secret
metadata:
  name: gcr-secret
  namespace: kube-system
  labels:
    app: gcr-creds
    version: v1.2
    kubernetes.io/minikube-addons: gcr-creds
type: Opaque
```
The value for application_default_credentials.json can be obtained with the following command:
```bash
base64 -w $HOME/.config/gcloud/application_default_credentials.json
```

3. Create the secret in kubernetes
```bash
kubectl create -f k8s/gcr-secret.yml
```

3. Create the replication controller:

```bash
kubectl create -f k8s/replicationController.yml
```

## DockerHub Image

- https://hub.docker.com/r/upmcenterprises/awsecr-creds/

## About

Built by UPMC Enterprises in Pittsburgh, PA. http://enterprises.upmc.com/
