"""egress-check helper: one raw DNS query to a public resolver. Prints ok if an answer came back, fail otherwise."""
import socket
import sys

q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
     b"\x07example\x03com\x00\x00\x01\x00\x01")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(q, (sys.argv[1] if len(sys.argv) > 1 else "1.1.1.1", 53))
    s.recv(512)
    print("ok")
except Exception:
    print("fail")
