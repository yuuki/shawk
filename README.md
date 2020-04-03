# Transtracer

[![Build Status](https://travis-ci.org/yuuki/transtracer.svg?branch=master)](https://travis-ci.org/yuuki/transtracer)
[![Latest Version](http://img.shields.io/github/release/yuuki/transtracer.svg?style=flat-square)](https://github.com/yuuki/transtracer/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/yuuki/transtracer)](https://goreportcard.com/report/github.com/yuuki/transtracer)
[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

Transtracer is a socket-based tracing infrastructure for discovering network dependencies among processes in distributed applications. Transtracer has an architecture of monitoring network sockets, which are endpoints of TCP connections, to trace the dependency.

## Contributions

- As long as applications use the TCP protocol stack in the Linux kernel, the dependencies are discovered by Transtracer.
- The monitoring does not affect the network delay of the applications because the processing that only reads the connection information from network sockets is independent of the application communication.

## System Overview

![System structure](/doc/images/system_structure.png "System configuration")

This figure shows the system conﬁguration for matching the connection information related to multiple hosts and for creating a dependency graph. Tracer running on each host sends connection information to the central Connection Management DataBase (CMDB).

![Socket diagnosis](/doc/images/socket_diagnosis.png "Socket diagnosis")

This figure shows how to retrieve socket information for TCP connections. When the Tracer process runs on the host, the Tracer process queries the Linux kernel and obtains a snapshot of the active TCP connection status from the socket corresponding to each connection. At the same time, the Tracer process acquires the process information corresponding to each connection. Then it links each connection and each process.

## Requirements

- OS: Linux
- RDBMS: PostgreSQL 10+

## Usage

### ttracerd

```shell-session
# ttracerd --dbuser ttracer --dbpass ttracer --dbhost 10.0.0.20 --dbname "ttctl"
```

Make ttracer run once.

```shell-session
# ttracerd --once --interval-sec 3 --dbuser ttracer --dbpass ttracer --dbhost 10.0.0.20 --dbname "ttctl"
```

### ttctl

```shell-session
$ ttctl --dbhost 10.0.0.20 --ipv4 10.0.0.10
10.0.0.10:80 (’nginx’, pgid=4656)
└<-- 10.0.0.11:many (’wrk’, pgid=5982) 10.0.0.10:80 (’nginx’, pgid=4656)
└--> 10.0.0.12:8080 (’python’, pgid=6111) 10.0.0.10:many (’fluentd’, pgid=2127)
└--> 10.0.0.13:24224 (’fluentd’, pgid=2001)
```

## Papers (including proceedings)

1. Yuuki Tsubouchi, Masahiro Furukawa, Ryosoke Matsumoto, Transtracer: Automatically Tracing for Processes Dependencies in Distributed Systems by Monitoring Endpoints of TCP/UDP, IPSJ Internet and Operation Technology Symposium (IOTS2019), Vol. 2019, pp. 64-71, 2019. [[paper](https://yuuk.io/papers/transtracer_iots2019.pdf)] [[slide](https://speakerdeck.com/yuukit/udptong-xin-falsezhong-duan-dian-falsejian-shi-niyoruhurosesujian-yi-cun-guan-xi-falsezi-dong-zhui-ji-8bc9ca63-0751-40fd-9ad5-2f1ea692b9b0)]

## License

[MIT](LICENSE)

## Author

[yuuki](https://github.com/yuuki)
