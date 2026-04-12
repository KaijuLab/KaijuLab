// Vulnerability triage: scan every function and annotate high-risk ones.
// Usage: run vuln_triage /path/to/binary
//
// Scans the binary for dangerous patterns (strcpy, gets, format-string, etc.),
// then auto-annotates functions with score >= 7 with a red note and score badge.

print("=== Vulnerability Triage ===");
print("");

if binary == "" {
    print("Error: pass the binary path as argument or load one in the TUI.");
} else {
    // Run the heuristic scanner
    let report = scan_vulnerabilities(binary);
    print(report);

    // Re-read scores and add notes for high-risk functions
    let scores_txt = get_vuln_scores(binary);
    print("");
    print("Annotating high-risk functions (score >= 7)...");

    // Parse score lines: "  0x<addr>  <name>  score=<N>"
    let lines = scores_txt.split('\n');
    let annotated = 0;
    for line in lines {
        if line.contains("score=") {
            // Extract score value
            let score_idx = line.find("score=");
            if score_idx >= 0 {
                let score_str = line.sub_string(score_idx + 6);
                let score = parse_int(score_str.trim());
                if score >= 7 {
                    // Extract address
                    let trimmed = line.trim();
                    if trimmed.starts_with("0x") {
                        let sp = trimmed.find(' ');
                        if sp > 0 {
                            let addr_str = trimmed.sub_string(0, sp);
                            let addr = parse_addr(addr_str);
                            add_note_at(binary, `High-risk function (vuln score ${score}/10)`, addr);
                            annotated += 1;
                        }
                    }
                }
            }
        }
    }
    print(`Done. Annotated ${annotated} high-risk function(s).`);
}
