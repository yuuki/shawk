# Image of the collector with the shawk connector, built by goreleaser from
# the binaries of a release. Mount the configuration at
# /etc/shawk/collector.yaml. shawk-migrate is included to apply the schema:
#   docker run --rm --entrypoint /shawk-migrate IMAGE -dsn postgres://...
#
# The base image is pinned by the digest of its index (all platforms); to
# update it, take the Docker-Content-Digest of
# https://gcr.io/v2/distroless/static-debian12/manifests/nonroot.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/shawk-collector /shawk-collector
COPY $TARGETPLATFORM/shawk-migrate /shawk-migrate
COPY LICENSE build/notices/shawk-collector/THIRD_PARTY_NOTICES /licenses/
EXPOSE 4317 4318 4327 4328
ENTRYPOINT ["/shawk-collector"]
CMD ["--config", "/etc/shawk/collector.yaml"]
