FROM golang:1.27.1

ENV PKG github.com/yuuki/shawk
WORKDIR /go/src/$PKG
