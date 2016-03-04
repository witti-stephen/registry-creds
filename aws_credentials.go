package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/golang/glog"
)

func main() {

	glog.Info("Starting up...")

	svc := ecr.New(session.New(), aws.NewConfig().WithRegion("us-east-1"))

	params := &ecr.GetAuthorizationTokenInput{
		RegistryIds: []*string{
			aws.String("886767563803"),
		},
	}

	resp, err := svc.GetAuthorizationToken(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return
	}

	// Pretty-print the response data.
	fmt.Println(resp.AuthorizationData[0].AuthorizationToken)
}
