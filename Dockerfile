FROM alpine:3.3
MAINTAINER Steve Sloka <slokas@upmc.edu>

RUN apk add --update ca-certificates && \
  rm -rf /var/cache/apk/*

ADD aws_credentials aws_credentials

ENTRYPOINT ["/aws_credentials"]
