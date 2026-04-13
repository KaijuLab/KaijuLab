
from pwn import *
import struct

binary_path = "./samples/PwnableTW/orw/orw"
bpf_offset = 0x640
bpf_length = 96

with open(binary_path, "rb") as f:
    f.seek(bpf_offset)
    bpf_bytes = f.read(bpf_length)

# Each BPF instruction is 8 bytes
# struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; };
# struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; };

# pwntools seccomp disassembler expects a list of tuples (code, jt, jf, k)
bpf_program = []
for i in range(0, len(bpf_bytes), 8):
    code, jt, jf, k = struct.unpack("<HBBI", bpf_bytes[i:i+8])
    bpf_program.append((code, jt, jf, k))

print("Disassembled BPF program:")
print(seccomp.disasm(bpf_program))
