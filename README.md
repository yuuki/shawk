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
$ ttctl --level 2 --dest-ipv4 10.0.0.21
10.0.0.21:80
└<-- 10.0.0.22:many ('nginx', pgid=2000, connections=30)
└<-- 10.0.0.23:many ('nginx', pgid=891, connections=30)
└<-- 10.0.0.24:many ('nginx', pgid=1002, connections=30)
        └<-- 10.0.0.30:many ('python', pgid=1889 connections=1)
        └<-- 10.0.0.31:many ('python', pgid=1998 connections=1)
└<-- 10.0.0.25:many (connections:30)

10.0.0.21:22
└<-- 10.0.0.100:many
```

## License

[MIT](LICENSE)

## Author

[yuuki](https://github.com/yuuki)
