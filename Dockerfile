FROM alpine:3.18 AS builder

USER root
RUN apk add bcc-tools bcc-dev bcc-doc go linux-headers

ADD src /src
WORKDIR /src

RUN go get
RUN go mod download
RUN go build -o go-tracer

FROM alpine:3.18

USER root
RUN apk add bcc-tools bcc-dev bcc-doc linux-headers

WORKDIR /src
COPY --from=builder /src/go-tracer /src/go-tracer

CMD "./go-tracer"
