FROM golang:1.15.5

ENV PKG github.com/yuuki/shawk
WORKDIR /go/src/$PKG
