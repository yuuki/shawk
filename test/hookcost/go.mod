module github.com/yuuki/shawk/test/hookcost

go 1.27.4

tool github.com/cilium/ebpf/cmd/bpf2go

require (
	github.com/cilium/ebpf v0.22.0
	github.com/yuuki/shawk v0.0.0
	golang.org/x/sys v0.49.0
)

replace github.com/yuuki/shawk => ../..
