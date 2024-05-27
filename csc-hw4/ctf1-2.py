#!/usr/bin/env python

from pwn import *
from ctypes import CDLL
from ctypes.util import find_library

libc = CDLL(find_library("c"))
libc.srand(libc.time(0))

r = remote('140.113.24.241', 30171)

secret = list(16 * b'\x00')
for i in range(16):
    secret[i] = 48 + (libc.rand() % (126-47) + 1)
secret = "".join([chr(x) for x in secret])

r.recvuntil(b'secret:')
r.sendline(b''.join([str(x).encode() for x in secret]))

# receive the flag
result = r.recvuntil(b'}').split()
print(result[-1].decode())

r.close()
