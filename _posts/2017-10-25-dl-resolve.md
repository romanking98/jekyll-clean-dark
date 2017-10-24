---
Layout: post
comments: true
title: Analysis of dl-resolve
---

Various Sections of an ELF:
```
vagrant@kali:~$ readelf -S warehouse 
There are 30 section headers, starting at offset 0x11ac:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048134 000134 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048148 000148 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048168 000168 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        0804818c 00018c 000024 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481b0 0001b0 0000a0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          08048250 000250 00007f 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          080482d0 0002d0 000014 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         080482e4 0002e4 000030 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048314 000314 000010 08   A  5   0  4
  [10] .rel.plt          REL             08048324 000324 000038 08  AI  5  12  4
  [11] .init             PROGBITS        0804835c 00035c 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        08048380 000380 000080 04  AX  0   0 16
  [13] .text             PROGBITS        08048400 000400 0002c2 00  AX  0   0 16
  [14] .fini             PROGBITS        080486c4 0006c4 000014 00  AX  0   0  4
  [15] .rodata           PROGBITS        080486d8 0006d8 00000b 00   A  0   0  4
  [16] .eh_frame_hdr     PROGBITS        080486e4 0006e4 000034 00   A  0   0  4
  [17] .eh_frame         PROGBITS        08048718 000718 0000e0 00   A  0   0  4
  [18] .init_array       INIT_ARRAY      080497f8 0007f8 000004 00  WA  0   0  4
  [19] .fini_array       FINI_ARRAY      080497fc 0007fc 000004 00  WA  0   0  4
  [20] .jcr              PROGBITS        08049800 000800 000004 00  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049804 000804 0000e8 08  WA  6   0  4
  [22] .got              PROGBITS        080498ec 0008ec 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        080498f0 0008f0 000028 04  WA  0   0  4
  [24] .data             PROGBITS        08049918 000918 000008 00  WA  0   0  4
  [25] .bss              NOBITS          08049920 000920 000008 00  WA  0   0  4
  [26] .comment          PROGBITS        00000000 000920 000039 01  MS  0   0  1
  [27] .shstrtab         STRTAB          00000000 000959 000106 00      0   0  1
  [28] .symtab           SYMTAB          00000000 000a60 000490 10     29  45  4
  [29] .strtab           STRTAB          00000000 000ef0 0002bc 00      0   0  1
```

dl_resolve(link_map,<some_pushed_val>)
link_map: linked list

### What is symtab ?

Meaning of this statement: ` Elf32_Sym *sym = &SYMTAB[((reloc->r_info)>>8)] `
reloc is pointer to relocation table. It finds something called r_info from there. Uses that and indexes from *SYMTAB* . Where is this magical
symbol table ?

```
gef> x/20xw 0x080481b0
0x80481b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x80481c0:	0x00000043	0x00000000	0x00000000	0x00000012
0x80481d0:	0x00000031	0x00000000	0x00000000	0x00000012
0x80481e0:	0x0000001a	0x00000000	0x00000000	0x00000012
0x80481f0:	0x0000005c	0x00000000	0x00000000	0x00000020
gef> 
0x8048200:	0x0000004a	0x00000000	0x00000000	0x00000012
0x8048210:	0x0000003e	0x00000000	0x00000000	0x00000012
0x8048220:	0x00000037	0x00000000	0x00000000	0x00000012
0x8048230:	0x0000000b	0x080486dc	0x00000004	0x000f0011
0x8048240:	0x0000002b	0x08049920	0x00000004	0x00190011
```
These values 0x43,0x31,0x1a etc are offsets into the *Symbol's String Table*. Where is that ? see .dynstr.

Add 0x43 to .dynstr base. See result.
```
gef> x/xs 0x08048250+0x43
0x8048293:	"strcmp"
gef> x/xs 0x08048250+0x44
0x8048294:	"trcmp"
gef> x/xs 0x08048250+0x42
0x8048292:	""
gef> x/xs 0x08048250+0x43
0x8048293:	"strcmp"
gef> x/xs 0x08048250+0x31
0x8048281:	"fgets"
gef> x/xs 0x08048250+0x1a
0x804826a:	"__stack_chk_fail"
gef> x/xs 0x08048250+0x5c
0x80482ac:	"__gmon_start__"
gef> 
```
Check this one out !!

```
0x8048230:	0x0000000b	0x080486dc	0x00000004	0x000f0011
gef> x/xs 0x08048250+0xb
0x804825b:	"_IO_stdin_used"
gef> x/xw 0x080486dc
0x80486dc <_IO_stdin_used>:	0x00020001
```


So there must be some struct or something.
Here it is !!

```
typedef struct {
Elf32_Word st_name;
Elf32_Addr st_value; 
Elf32_Word st_size; 
unsigned char st_info; 
unsigned char st_other; 
Elf32_Half st_shndx;
} Elf32_Sym;
```

So that size is 4 + 4 + 4 + 1 + 1 + 2 = (perfect) 16 bytes

### RELOCATION

```
typedef struct {
Elf32_Addr r_offset;
Elf32_Word r_info;
} Elf32_Rel;
```

This is what a relocation entry struct is. Check the .rel.dyn ELF section.
Lets see in gdb.

```
gef> x/20xw 0x08048314
0x8048314:	0x080498ec	0x00000406	0x08049920	0x00000905
0x8048324:	0x080498fc	0x00000107	0x08049900	0x00000207
0x8048334:	0x08049904	0x00000307	0x08049908	0x00000407
0x8048344:	0x0804990c	0x00000507	0x08049910	0x00000607
0x8048354:	0x08049914	0x00000707	0x08ec8353	0x0000cbe8
```
These addresses all point to the GOT table of the ELF. Yes these r_offset *in this case* is the actual virtual address (Think of it like offset from 0).
Just to make sure:
```
gef> x/xw 0x080498fc
0x80498fc <strcmp@got.plt>:	0x08048396
gef> 
```

But what's r_info ?
remember the formula that we didn't understand ?

` Elf32_Sym *sym = &SYMTAB[((reloc->r_info)>>8)] `

Yep that one. So that is what is referenced from SYMTAB as base.
So whats happening is program jumps to this region, figures out the r_offset for the appropiate GOT_address and uses its r_info.
It then maps that to the symbol_memory_layout that we saw that was filled with the struct ELF32_Sym. From there, it gets the symbol's name,address,type,scope(local/global) everything. (like we saw with _IO_stdin_used)

### .dynamic

.dynamic is another section header in ELF. Lets see what it contains:

```
gef> x/20xw 0x08049804
0x8049804:	0x00000001	0x00000001	0x0000000c	0x0804835c
0x8049814:	0x0000000d	0x080486c4	0x00000019	0x080497f8
0x8049824:	0x0000001b	0x00000004	0x0000001a	0x080497fc
0x8049834:	0x0000001c	0x00000004	0x6ffffef5	0x0804818c
0x8049844:	0x00000005	0x08048250	0x00000006	0x080481b0
gef> x/xw 0x0804835c
0x804835c <_init>:	0x08ec8353
gef> x/xw 0x080486c4
0x80486c4 <_fini>:	0x08ec8353
```

Basically pointers to _init, __global_dtors_aux (The kind of things u definitely wanna overwrite with a fms ;)

Finally, now that the ELF knows everything about the function it has to find in the libc, it resolves it.

`result = _dl_lookup_symbol_x (strtab + sym-> st_name, l, & sym, l-> l_scope, version, ELF_RTYPE_CLASS_PLT, flags, NULL );`

Once resolved, this entire process need not be repeated for that function since the got entry would now be filled with the actual libc address......coz now the program knows right !!
