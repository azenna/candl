from pwn import *

io = process("ascii-shellcode-32", env={"PATH":"."})

io.interactive()
