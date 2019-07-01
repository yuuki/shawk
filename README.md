# Transtracer

[licence]: https://github.com/yuuki/transtracer/blog/master/LICENSE

Transtracer is a tracing infrastructure for discovering network services dependecies on the transport network layer.

## System Overview

## Usage

### ttctl

```shell
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
