// Entropy report: print section entropy and flag packed / encrypted sections.
// Usage: run entropy_report /path/to/binary

if binary == "" {
    print("Error: pass the binary path.");
} else {
    print("=== Section Entropy Report ===");
    print("");
    let result = section_entropy(binary);
    print(result);

    // Heuristic: anything > 7.0 entropy is suspicious
    let lines = result.split('\n');
    let high_entropy = [];
    for line in lines {
        if line.contains("7.") || line.contains("8.") || line.contains("9.") {
            if !line.trim().starts_with("File") && !line.trim().starts_with("Section") {
                high_entropy += [line.trim()];
            }
        }
    }

    if high_entropy.len() > 0 {
        print("⚠  High-entropy sections (possible packing/encryption):");
        for s in high_entropy {
            print(`  ${s}`);
        }
        add_note(binary, "High-entropy sections detected — possible packing or encryption");
    } else {
        print("No suspiciously high-entropy sections found.");
    }
}
