FROM golang:1.15.0

ENV PKG github.com/yuuki/shawk
WORKDIR /go/src/$PKG
