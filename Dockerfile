FROM golang:1.26.5-alpine AS build
# ca-certificates: the scratch runtime has no trust store, so the Go server's
# outbound HTTPS (protect mode: OIDC discovery + token + userinfo to hanzo.id)
# would fail x509 verification ("certificate signed by unknown authority").
# Copy the CA bundle into the final image so server-side TLS verifies.
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /spa .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /spa /spa
ENTRYPOINT ["/spa"]
