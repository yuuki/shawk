FROM golang:1.14.2

ENV PKG github.com/yuuki/shawk
WORKDIR /go/src/$PKG
