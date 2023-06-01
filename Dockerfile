FROM alpine:3.18 AS base

USER root
RUN apk add bcc-tools bcc-dev bcc-doc linux-headers

FROM base AS builder

RUN apk add go

ADD src /src
WORKDIR /src

RUN go get
RUN go mod download
RUN go build -o go-tracer

FROM base

WORKDIR /src
COPY --from=builder /src/go-tracer /src/go-tracer

CMD "./go-tracer"
