FROM golang:1.14.1

ENV PKG github.com/yuuki/shawk
WORKDIR /go/src/$PKG
