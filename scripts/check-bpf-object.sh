#!/usr/bin/env bash
# Checks that the committed BPF object, which the binary embeds, matches the
# BPF source: the object is compiled again and both are compared by
# TestCommittedObject. The committed object is restored afterwards.
set -euo pipefail

obj=internal/tracer/bpf_bpfel.o
work="$(mktemp -d)"
cp "$obj" "$work/committed.o"
trap 'cp "$work/committed.o" "$obj"; rm -rf "$work"' EXIT

go generate ./internal/tracer/
git diff --exit-code -- internal/tracer/bpf_bpfel.go
cp "$obj" "$work/fresh.o"
cp "$work/committed.o" "$obj"
SHAWK_FRESH_OBJECT="$work/fresh.o" go test -count=1 -run TestCommittedObject -v ./internal/tracer/
