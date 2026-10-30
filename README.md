# shawk

<img alt="shawk-logo" src="docs/images/logo.png" width="160">

**A dependency ledger for your servers.** shawk records which process talks
to which network service on every host with eBPF, keeps the record for
years, and answers the questions you ask before changing a system:

```console
$ shawk who-uses db-01:5432 -depth 2
db-01:5432/tcp (10.0.0.10)  postgres (postgresql.service)  conns=1.2M bytes=12.4GiB/3.1GiB last=just now
├── app-01 (10.0.0.11)  puma (app.service)  conns=1.2M open=40 bytes=3.1GiB/12.4GiB last=just now
│   └── app-01:8080/tcp (10.0.0.11)  puma (app.service)  conns=8.1M last=just now
│       └── lb-01 (10.0.0.5)  haproxy (haproxy.service)  conns=8.1M last=just now
├── batch-03 (10.0.0.31)  ruby (monthly-report.service)  conns=12 last=2026-10-01
└── 10.0.8.7  (no agent)  conns=3 last=2026-08-14

$ shawk can-i-remove old-cache-02
NO: old-cache-02 is still used by remote processes since 2026-09-30 12:00:00:
old-cache-02:11211/tcp (10.0.0.42)  memcached (memcached.service)  conns=31 last=3d ago
└── app-07 (10.0.0.17)  php-fpm (php-fpm.service)  conns=31 last=3d ago
```

* **Zero instrumentation.** Dependencies are observed at TCP/UDP sockets in
  the kernel, so every process is covered — your code, middleware,
  third-party software, cron jobs — whatever language it is written in.
* **Low overhead, always on.** Flows to the same service are bundled in the
  kernel; TCP is traced at connection state changes only, with no hook on the
  send/receive path. Rare dependencies such as monthly batch jobs are not
  missed by sampling.
* **History, not just a live map.** Each host keeps a ledger of its
  dependencies with first/last seen times and per-minute/hour/day activity.
* **No central database.** Each agent owns the ledger of its host; queries
  walk dependencies across agents.

shawk implements the socket-based tracing with in-kernel flow bundling from
[Low Overhead TCP/UDP Socket-based Tracing for Discovering Network Services
Dependencies](https://yuuk.io/papers/transtracer_jip2022.pdf) (JIP, 2022).
See [docs/design.md](docs/design.md) for the design.

## Requirements

* Linux 5.14 or later with BTF (`/sys/kernel/btf/vmlinux`), e.g. Rocky Linux /
  RHEL 9, Ubuntu 22.04+, Debian 12+. Tested on x86_64; arm64 is expected to
  work but untested.
* UDP tracing additionally needs BPF trampolines (fentry), available on
  x86_64 and on arm64 since Linux 6.0. Without them only TCP is traced.
* The agent runs as root.

## Install

shawk is a single static binary.

```bash
make build                      # builds ./shawk (needs Go only)
sudo install -m 0755 shawk /usr/local/bin/shawk
sudo install -m 0644 packaging/systemd/shawk-agent.service /etc/systemd/system/
sudo systemctl enable --now shawk-agent
```

Run the agent on every host you want to observe. It listens on TCP port
7464; open it to the hosts you run queries from. To require a token, write
it to a file and pass `-token-file` to the agent and the clients (or set
`SHAWK_TOKEN_FILE`).

## Usage

Targets are `HOST[:PORT][/UNIT]` or `HOST[:PORT][/@COMM]`, where `HOST` is a
host name or an address of a host running the agent.

| command | |
|---|---|
| `shawk agent` | run the agent (see `shawk agent -h` for retention and interval) |
| `shawk flows` | show bundled flows on this host live, without an agent |
| `shawk who-uses TARGET [-depth N]` | processes that use services on TARGET, transitively upstream |
| `shawk deps TARGET [-depth N]` | services that processes on TARGET use, transitively downstream |
| `shawk can-i-remove TARGET` | whether remote processes used TARGET; exits 1 if so |
| `shawk unused TARGET` | listening services that nobody used |
| `shawk diff TARGET -since 24h` | dependencies that appeared or disappeared |
| `shawk graph TARGET... [-format mermaid\|dot\|json]` | export the dependency graph |
| `shawk status TARGET` | agent status and BPF program statistics |

Every query accepts `-since` (default `30d`; units `m`, `h`, `d`, `w`) and
`-json`.

```console
$ shawk deps lb-01 -depth 3
lb-01 (10.0.0.5)  haproxy (haproxy.service)
└── app-01:8080/tcp (10.0.0.11)  puma (app.service)  conns=8.1M last=just now
    ├── db-01:5432/tcp (10.0.0.10)  postgres (postgresql.service)  conns=1.2M open=40 last=just now
    ├── app-01:6379/tcp (10.0.0.11)  redis-server (redis.service)  conns=8.1M last=just now
    └── 10.0.0.2:53/udp  (no agent)  msgs=310k last=just now

$ shawk diff app-01 -since 2h
+  puma (app.service)  -> 10.0.0.20:6379/tcp        first seen 2026-10-30 10:12:41
-  puma (app.service)  -> 10.0.0.21:11211/tcp       last seen 2026-10-29 23:58:02

$ shawk graph app-01 -depth 3 -format mermaid
flowchart LR
  ...
```

## Development

```bash
make generate   # compile the BPF programs (needs clang)
make test       # unit tests
make test-root  # load the BPF programs into the running kernel (sudo)
make e2e        # multi-host test with network namespaces (sudo)
make compat     # check CO-RE relocations against the Rocky Linux 9 kernel
```

The generated BPF object (`internal/tracer/bpf_bpfel.o`) is committed, so
building shawk needs only Go.

## History

shawk started as *Transtracer* ([IOTS 2019](https://yuuk.io/papers/shawk_iots2019.pdf))
and was rewritten from scratch in 2026, replacing the previous polling and
streaming probes, the central PostgreSQL CMDB and
[go-conntracer-bpf](https://github.com/yuuki/go-conntracer-bpf).

## License

The Go code is [MIT](LICENSE). The BPF programs in `internal/tracer/bpf`
are dual-licensed GPL-2.0-only OR BSD-2-Clause.
