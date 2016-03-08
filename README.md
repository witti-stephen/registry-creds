# AWS ECR Credentials
Allow for AWS ECR credentials to be refreshed inside your Kubernetes cluster via ImagePullSecrets

## How it works

1. The tool runs as a container in the `kube-system` namespace.
- It gets credentials from AWS ECR via the aws-go sdk
- Next it creates a secret named `awsecr-creds` (by default)
- Then it sets up this secret to be used in the `ImagePullSecrets` for the default service account
- Whenever a pod is created, this secret is attached to the pod
- The container will refresh the credentials by default every 11 hours 55 minutes since they expire at 12 hours

## How to setup

1. Edit the sample [replication controller](k8s/replicationController.yml) and update with your AWS account id
- Create the replication controller
    ```
    kubectl create -f k8s/replicationController.yml
    ```

- Make sure your EC2 instances have the following IAM permissions:
    ```
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

## About

Built by UPMC Enterprises in Pittsburgh, PA. http://enterprises.upmc.com/
