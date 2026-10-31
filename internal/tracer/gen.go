package tracer

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -mcpu=v3" -target bpfel -type shawk_flow_key -type shawk_flow_stats -type shawk_iter_rec -type shawk_cgroup_event bpf bpf/shawk.bpf.c -- -I./bpf/include
