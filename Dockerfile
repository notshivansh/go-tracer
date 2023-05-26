FROM alpine:3.18

USER root
RUN apk add bcc-tools bcc-dev bcc-doc git go linux-headers

ADD src /src
WORKDIR /src

RUN go get
RUN go mod download
RUN go build -o go-tracer

CMD "./go-tracer"
