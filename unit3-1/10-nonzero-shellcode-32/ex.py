from pwn import *
import os

io = process('./nonzero-shellcode-32', env={})

import re
io.sendlineafter(b'Reading', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
