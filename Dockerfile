FROM --platform=$BUILDPLATFORM golang:1.23-alpine as builder
ARG TARGETOS TARGETARCH

WORKDIR /go/src/app
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build .

FROM scratch
COPY --from=builder /etc/ssl/cert.pem /etc/ssl/cert.pem
COPY --from=builder /go/src/app/acmevault /bin/acmevault
ENTRYPOINT ["/bin/acmevault"]
