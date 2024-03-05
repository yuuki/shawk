FROM golang:1.22.1

ENV PKG github.com/yuuki/shawk
WORKDIR /go/src/$PKG
