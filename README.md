# Transtracer

[licence]: https://github.com/yuuki/transtracer/blog/master/LICENSE

Transtracer is a tracing infrastructure for discovering network services dependecies on the transport network layer.

## System Overview

## Usage

### CLI

```shell
transtracer --level 2 --dest-ipv4 10.0.0.21
10.0.0.21:8000
└<-- 10.0.0.22:many nginx (connections:30)
└<-- 10.0.0.23:many nginx (connections:30)
└<-- 10.0.0.24:many nginx (connections:30)
        └<-- 10.0.0.30:many app2 (connections:1)
        └<-- 10.0.0.31:many app2 (connections:1)
└<-- 10.0.0.25:many (connections:30)

10.0.0.21:22
└<-- 10.0.0.100:many
```
