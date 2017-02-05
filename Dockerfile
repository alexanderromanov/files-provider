FROM alpine

RUN apk add --no-cache ca-certificates openssl
ADD files-provider /

ENTRYPOINT /files-provider

EXPOSE 8000