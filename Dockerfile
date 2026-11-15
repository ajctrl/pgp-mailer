# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# Static binary: OpenPGP, bbolt and TLS are all pure Go.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pgp-mailer ./cmd/pgp-mailer \
 && mkdir -p /out/queue

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pgp-mailer /pgp-mailer
# Pre-created and owned by nonroot (65532) so that a fresh named volume
# mounted here is writable. Everything else in the container is read-only.
COPY --from=build --chown=65532:65532 /out/queue /var/lib/pgp-mailer
USER 65532:65532
VOLUME /var/lib/pgp-mailer
EXPOSE 8080
# distroless has no shell or curl; the binary checks itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/pgp-mailer", "healthcheck"]
ENTRYPOINT ["/pgp-mailer"]
CMD ["serve"]
