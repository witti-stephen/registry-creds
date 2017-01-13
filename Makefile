# Makefile for the Docker image upmcenterprises/registry-creds
# MAINTAINER: Steve Sloka <slokas@upmc.edu>
# If you update this image please bump the tag value before pushing.

.PHONY: all binary container push clean test

TAG = 1.4
PREFIX = upmcenterprises

all: container

binary: main.go
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -installsuffix cgo -o registry-creds --ldflags '-w' ./main.go

container: binary
	docker build -t $(PREFIX)/registry-creds:$(TAG) .

push:
	docker push $(PREFIX)/registry-creds:$(TAG)

clean:
	rm -f registry-creds

test: clean
	go test $(go list ./... | grep -v /vendor/)
