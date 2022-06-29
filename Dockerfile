
FROM --platform=$BUILDPLATFORM golang:1.18-alpine as builder
ARG TARGETOS TARGETARCH

WORKDIR /go/src/app
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build .

FROM scratch
COPY --from=builder /go/src/app/acmevault /bin/acmevault
ENTRYPOINT ["/bin/acmevault"]
