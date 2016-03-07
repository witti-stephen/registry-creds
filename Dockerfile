FROM scratch
MAINTAINER Steve Sloka <slokas@upmc.edu>
ADD aws_credentials aws_credentials
ENTRYPOINT ["/aws_credentials"]
