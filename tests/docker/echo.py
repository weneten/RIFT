#!/usr/bin/env python3
import socket
import sys
import threading


def serve(family, kind, address, port):
    sock = socket.socket(family, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    if kind == socket.SOCK_STREAM:
        sock.listen(32)
        while True:
            conn, peer = sock.accept()
            try:
                conn.sendall(peer[0].encode())
            finally:
                conn.close()
    else:
        while True:
            _, peer = sock.recvfrom(4096)
            sock.sendto(peer[0].encode(), peer)


if len(sys.argv) != 3:
    raise SystemExit("usage: rift-echo.py TUNNEL_IPV4 TUNNEL_IPV6")

for family, address in ((socket.AF_INET, sys.argv[1]),
                        (socket.AF_INET6, sys.argv[2])):
    for kind, port in ((socket.SOCK_STREAM, 19080), (socket.SOCK_DGRAM, 19081)):
        threading.Thread(target=serve, args=(family, kind, address, port), daemon=True).start()

threading.Event().wait()
