FROM golang:1.14.0

ENV PKG github.com/yuuki/transtracer
WORKDIR /go/src/$PKG
