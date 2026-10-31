"""A toy network service for the end-to-end test.

It serves HTTP on --listen and calls each --upstream (HTTP) per request.
With --persist it keeps one TCP connection to HOST:PORT open and writes to
it every second, like a connection pool.
"""
import argparse
import http.client
import http.server
import socket
import threading
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", type=int, action="append", default=[])
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--upstream", action="append", default=[])
    p.add_argument("--persist")
    p.add_argument("--client", help="request HOST:PORT periodically instead of serving")
    args = p.parse_args()

    if args.persist:
        threading.Thread(target=persist, args=(args.persist,), daemon=True).start()

    if args.client:
        host, port = args.client.rsplit(":", 1)
        while True:
            try:
                c = http.client.HTTPConnection(host, int(port), timeout=2)
                c.request("GET", "/")
                c.getresponse().read()
                c.close()
            except OSError:
                pass
            time.sleep(0.5)

    upstreams = [u.rsplit(":", 1) for u in args.upstream]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            for host, port in upstreams:
                try:
                    c = http.client.HTTPConnection(host, int(port), timeout=2)
                    c.request("GET", "/")
                    c.getresponse().read()
                    c.close()
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
    servers = [http.server.ThreadingHTTPServer((args.bind, port), Handler) for port in args.listen]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    servers[0].serve_forever()


def persist(target):
    host, port = target.rsplit(":", 1)
    while True:
        try:
            s = socket.create_connection((host, int(port)), timeout=2)
            while True:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                s.recv(4096)
                time.sleep(1)
        except OSError:
            time.sleep(1)


if __name__ == "__main__":
    main()
