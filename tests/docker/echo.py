#!/usr/bin/env python3
import socket
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


for family, address in ((socket.AF_INET, "10.88.0.2"),
                        (socket.AF_INET6, "fd88:5249:4654::2")):
    for kind, port in ((socket.SOCK_STREAM, 19080), (socket.SOCK_DGRAM, 19081)):
        threading.Thread(target=serve, args=(family, kind, address, port), daemon=True).start()

threading.Event().wait()
