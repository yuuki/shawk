package tracer

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -mcpu=v3" -target bpfel -type shawk_flow_key -type shawk_flow_stats -type shawk_iter_rec -type shawk_cgroup_event -type shawk_peer_prefix -type shawk_xlat_key -type shawk_xlat_stats -type shawk_xlat_conn -type shawk_unix_key -type shawk_unix_stats -type shawk_unix_conn bpf bpf/shawk.bpf.c -- -I./bpf/include
