# Image of the collector with the shawk connector, built by goreleaser from
# the binaries of a release. Mount the configuration at
# /etc/shawk/collector.yaml. shawk-migrate is included to apply the schema:
#   docker run --rm --entrypoint /shawk-migrate IMAGE -dsn postgres://...
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/shawk-collector /shawk-collector
COPY $TARGETPLATFORM/shawk-migrate /shawk-migrate
COPY LICENSE build/notices/shawk-collector/THIRD_PARTY_NOTICES /licenses/
EXPOSE 4317 4318 4327 4328
ENTRYPOINT ["/shawk-collector"]
CMD ["--config", "/etc/shawk/collector.yaml"]
