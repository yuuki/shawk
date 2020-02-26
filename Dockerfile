FROM golang:1.14.0

ENV PKG github.com/yuuki/transtracer
WORKDIR /go/src/$PKG

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN make build
