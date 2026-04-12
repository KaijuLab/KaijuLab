// Hello World — minimal plugin template to verify the scripting engine works.
// Usage: run hello  (or: run hello /path/to/binary)

print("Hello from KaijuLab Rhai scripting!");
print("");
print(`Current binary: ${binary}`);
print(`Plugins directory: ${plugins_dir()}`);
print("");

// Demonstrate the utility functions
let addr = parse_addr("0x401000");
print(`parse_addr("0x401000") = ${addr}`);
print(`hex(${addr}) = ${hex(addr)}`);
