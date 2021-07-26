FROM golang:1.16-alpine

RUN apk add --no-cache curl git && rm -rf /var/cache/apk/*

WORKDIR /go/src/github.com/jpbetz/auger
ADD     . /go/src/github.com/jpbetz/auger
RUN     go get github.com/jpbetz/auger && chmod +x /go/bin/auger

ENTRYPOINT ["/go/bin/auger"]
