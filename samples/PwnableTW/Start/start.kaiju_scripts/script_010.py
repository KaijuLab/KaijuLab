from pwn import *
context.arch = "i386"
p = process("./samples/PwnableTW/Start/start")