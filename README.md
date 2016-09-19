# AWS ECR Credentials
Allow for AWS ECR credentials to be refreshed inside your Kubernetes cluster via ImagePullSecrets

## How it works

1. The tool runs as a pod in the `kube-system` namespace.
- It gets credentials from AWS ECR via the aws-go sdk
- Next it creates a secret named `awsecr-creds` (by default)
- Then it sets up this secret to be used in the `ImagePullSecrets` for the default service account
- Whenever a pod is created, this secret is attached to the pod
- The container will refresh the credentials by default every 11 hours 55 minutes since they expire at 12 hours

_NOTE: This will setup credentials across ALL namespaces!_

## How to setup running in AWS

1. Clone the repo and navigate to directory

2. Edit the sample [replication controller](k8s/replicationController.yml) and update with your AWS account id

3. Create the replication controller

  ```bash
  kubectl create -f k8s/replicationController.yml
  ```

4. Make sure your EC2 instances have the following IAM permissions:

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

### Note:
If you are not running in AWS Cloud, then you can still use this tool! Simply add the following environment variables to your replication controller:
```
AWS_ACCESS_KEY_ID=AKID1234567890
AWS_SECRET_ACCESS_KEY=MY-SECRET-KEY
```

## DockerHub Image

- https://hub.docker.com/r/upmcenterprises/awsecr-creds/

## About

Built by UPMC Enterprises in Pittsburgh, PA. http://enterprises.upmc.com/
