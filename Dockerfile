FROM golang:1.10-alpine

RUN apk add --no-cache curl git && rm -rf /var/cache/apk/*
RUN curl https://glide.sh/get | sh

WORKDIR /go/src/github.com/kubernetes-incubator/auger
ADD     . /go/src/github.com/kubernetes-incubator/auger
RUN     glide install -v && go install -v github.com/kubernetes-incubator/auger && chmod +x /go/bin/auger

ENTRYPOINT ["/go/bin/auger"]
