# Transtracer

[![Build Status](https://travis-ci.org/yuuki/transtracer.svg?branch=master)](https://travis-ci.org/yuuki/transtracer)
[![Latest Version](http://img.shields.io/github/release/yuuki/transtracer.svg?style=flat-square)](https://github.com/yuuki/transtracer/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/yuuki/transtracer)](https://goreportcard.com/report/github.com/yuuki/transtracer)
[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

Transtracer is a tracing infrastructure for discovering network services dependecies on the transport network layer.

## System Overview

![System structure](/doc/images/system_structure.png "System structure")
![Socket diagnosis](/doc/images/socket_diagnosis.png "Socket diagnosis")

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

## License

[MIT](LICENSE)

## Author

[yuuki](https://github.com/yuuki)
