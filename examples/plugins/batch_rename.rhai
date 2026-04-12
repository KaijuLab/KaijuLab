// Batch rename: apply a list of vaddr→name pairs from an embedded table.
// Useful for fast, repeatable annotation of known binaries.
// Usage: run batch_rename /path/to/binary
//
// Edit the RENAMES map below to match your target binary.

if binary == "" {
    print("Error: pass the binary path.");
} else {
    // ── Edit this table for your target ──────────────────────────────────────
    let RENAMES = #{
        "0x401000": "main",
        "0x401234": "parse_config",
        "0x401500": "handle_request",
        "0x401800": "send_response",
    };
    // ─────────────────────────────────────────────────────────────────────────

    print(`Applying ${RENAMES.len()} renames to ${binary}...`);
    let ok = 0;
    for entry in RENAMES {
        let addr = parse_addr(entry.key);
        let name = entry.value;
        let result = rename_function(binary, addr, name);
        if result.contains("Error") {
            print(`  FAIL  ${hex(addr)} → ${name}: ${result}`);
        } else {
            print(`  OK    ${hex(addr)} → ${name}`);
            ok += 1;
        }
    }
    print(`Done. ${ok}/${RENAMES.len()} renames applied.`);
}
