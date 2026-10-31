#!/bin/sh
# Generates the sources of the collector with the shawk connector in
# collector/_build with the OpenTelemetry Collector Builder, for the given
# version, without compiling them (goreleaser compiles them).
# Usage: scripts/generate-collector.sh VERSION
set -eu
version="${1:?usage: generate-collector.sh VERSION}"
ocb_version="${OCB_VERSION:-v0.164.0}"
cd "$(dirname "$0")/../collector"
manifest=_release-builder-config.yaml
trap 'rm -f "$manifest"' EXIT
sed "s/^  version: dev\$/  version: $version/" builder-config.yaml >"$manifest"
go run "go.opentelemetry.io/collector/cmd/builder@$ocb_version" --config "$manifest" --skip-compilation
