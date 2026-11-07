# Security policy

The shawk agent runs as root on every host: it loads eBPF programs into the
kernel, reads `/proc`, the cgroup hierarchy and the state files of container
runtimes, and enters every network namespace. The connector receives the
requests of agents over the network and writes to PostgreSQL. Issues that let
a local user, a container, an agent or another network client get more than
the design grants them are taken seriously, for example:

- crashing or stalling the agent or the connector from a process, a cgroup,
  a container or a request;
- making the connector write as another host, or make series in Prometheus
  beyond the bounds of [design §5.5](docs/design.md#55-bounds-of-what-is-held);
- getting from the agent what it reads but does not send, such as the
  environment of processes beyond their `OTEL_` variables;
- weaknesses of the systemd units, the packaged configuration or the
  PostgreSQL grants of `packaging/`.

The limits documented in [design §10](docs/design.md#10-limitations), such
as what is not traced, are not vulnerabilities.

## Supported versions

Security fixes are made on the `main` branch and released in the next
version. Only the latest release is supported.

## Reporting a vulnerability

Please do **not** open a public issue, pull request or discussion.

Report the vulnerability privately with GitHub's
[private vulnerability reporting](https://github.com/yuuki/shawk/security/advisories/new)
(the "Report a vulnerability" button of the Security tab). If that is not
possible, contact the author privately via the contact information on
https://github.com/yuuki.

Please include the version (`shawk version`, or the release of the collector
image), the kernel and distribution, the configuration involved, what an
attacker controls (a process on the host, a container, a cgroup, an agent or
its certificate, the network), and the impact. You should receive an answer
within a few weeks; shawk is maintained on a best-effort basis.

## Verifying releases

The archives, packages and the image `ghcr.io/yuuki/shawk-collector` of a
release have an attestation of their build provenance, made by the release
workflow of this repository:

```bash
gh attestation verify FILE --repo yuuki/shawk
gh attestation verify oci://ghcr.io/yuuki/shawk-collector:VERSION --repo yuuki/shawk
```
