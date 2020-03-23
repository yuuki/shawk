FROM golang:1.14.1

ENV PKG github.com/yuuki/transtracer
WORKDIR /go/src/$PKG
