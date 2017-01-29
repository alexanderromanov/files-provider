FROM golang:alpine

RUN mkdir -p /go/src/github.com/alexanderromanov/files-provider

ADD . /go/src/github.com/alexanderromanov/files-provider

RUN go install github.com/alexanderromanov/files-provider

ENTRYPOINT /go/bin/files-provider

EXPOSE 8000