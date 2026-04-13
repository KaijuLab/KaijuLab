
print("hello")
from pwn import *
p = process('./samples/PwnableTW/Start/start')
p.interactive()
