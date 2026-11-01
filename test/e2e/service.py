"""A toy network service for the end-to-end test.

It serves HTTP on --listen and calls each --upstream (HTTP) per request.
With --persist it keeps one TCP connection to HOST:PORT open and writes to
it every second, like a connection pool. It echoes UDP datagrams on
--udp-listen, and sends a datagram to each --udp-upstream per request and
waits for the reply, like a resolver. Addresses may be IPv6 ([::1]:80).
"""
import argparse
import http.client
import http.server
import socket
import threading
import time


def split_hostport(target):
    host, port = target.rsplit(":", 1)
    return host.strip("[]"), int(port)


def family(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", type=int, action="append", default=[])
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--upstream", action="append", default=[])
    p.add_argument("--persist")
    p.add_argument("--udp-listen", type=int, action="append", default=[])
    p.add_argument("--udp-upstream", action="append", default=[])
    p.add_argument("--client", help="request HOST:PORT periodically instead of serving")
    args = p.parse_args()

    if args.persist:
        threading.Thread(target=persist, args=(args.persist,), daemon=True).start()
    for port in args.udp_listen:
        threading.Thread(target=udp_echo, args=(args.bind, port), daemon=True).start()

    if args.client:
        host, port = split_hostport(args.client)
        while True:
            try:
                c = http.client.HTTPConnection(host, port, timeout=2)
                c.request("GET", "/")
                c.getresponse().read()
                c.close()
            except OSError:
                pass
            time.sleep(0.5)

    upstreams = [split_hostport(u) for u in args.upstream]
    udp_upstreams = [split_hostport(u) for u in args.udp_upstream]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            for host, port in upstreams:
                try:
                    c = http.client.HTTPConnection(host, port, timeout=2)
                    c.request("GET", "/")
                    c.getresponse().read()
                    c.close()
                except OSError:
                    pass
            for host, port in udp_upstreams:
                try:
                    with socket.socket(family(host), socket.SOCK_DGRAM) as u:
                        u.settimeout(2)
                        u.sendto(b"query", (host, port))
                        u.recvfrom(512)
                except OSError:
                    pass
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    # HTTP/1.1 keeps connections alive for --persist clients.
    Handler.protocol_version = "HTTP/1.1"

    class Server(http.server.ThreadingHTTPServer):
        address_family = family(args.bind)

    servers = [Server((args.bind, port), Handler) for port in args.listen]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    if servers:
        servers[0].serve_forever()
    while True:
        time.sleep(3600)


def udp_echo(bind, port):
    with socket.socket(family(bind), socket.SOCK_DGRAM) as u:
        u.bind((bind, port))
        while True:
            data, peer = u.recvfrom(512)
            u.sendto(data, peer)


def persist(target):
    host, port = split_hostport(target)
    while True:
        try:
            s = socket.create_connection((host, port), timeout=2)
            while True:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                s.recv(4096)
                time.sleep(1)
        except OSError:
            time.sleep(1)


if __name__ == "__main__":
    main()
