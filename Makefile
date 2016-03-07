# Makefile for the Docker image upmcenterprises/awsecr-creds
# MAINTAINER: Steve Sloka <slokas@upmc.edu>
# If you update this image please bump the tag value before pushing.

.PHONY: all emmie container push clean test

TAG = 1.0
PREFIX = upmcenterprises

all: container

server: aws_credentials.go
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo --ldflags '-w' ./aws_credentials.go

container: aws_credentials
	docker build -t $(PREFIX)/awsecr-creds:$(TAG) .

push:
	docker push $(PREFIX)/awsecr-creds:$(TAG)

clean:
	rm -f awsecr-creds

test: clean
	godep go test -v --vmodule=*=4
