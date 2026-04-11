//! DWARF debug-information parser.
//!
//! Extracts function names, addresses, and sizes from `.debug_info` / `.debug_abbrev`
//! using the `gimli` crate.  Returns a best-effort list; binaries without debug info
//! return an empty list rather than an error.

use object::{Object, ObjectSection};

pub struct DwarfFunction {
    pub name: String,
    pub addr: u64,
    pub size: Option<u64>,
}

/// Parse DWARF subprogram entries from the binary at `path`.
pub fn parse_dwarf_functions(path: &str) -> anyhow::Result<Vec<DwarfFunction>> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", path, e))?;

    let obj = object::File::parse(&*data)
        .map_err(|e| anyhow::anyhow!("Cannot parse binary: {}", e))?;

    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    // Helper closure to load a section's bytes as a gimli EndianSlice.
    let load_section = |name: &str| -> gimli::EndianSlice<'_, gimli::RunTimeEndian> {
        let bytes: &[u8] = obj
            .section_by_name(name)
            .and_then(|s| s.data().ok())
            .unwrap_or(b"");
        gimli::EndianSlice::new(bytes, endian)
    };

    let dwarf = gimli::Dwarf {
        debug_abbrev: gimli::DebugAbbrev::from(load_section(".debug_abbrev")),
        debug_info: gimli::DebugInfo::from(load_section(".debug_info")),
        debug_str: gimli::DebugStr::from(load_section(".debug_str")),
        debug_line: gimli::DebugLine::from(load_section(".debug_line")),
        debug_addr: gimli::DebugAddr::from(load_section(".debug_addr")),
        ranges: gimli::RangeLists::new(
            gimli::DebugRanges::from(load_section(".debug_ranges")),
            gimli::DebugRngLists::from(load_section(".debug_rnglists")),
        ),
        ..Default::default()
    };

    let mut funcs: Vec<DwarfFunction> = Vec::new();

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };

        let mut entries = unit.entries();
        while let Ok(Some((_, entry))) = entries.next_dfs() {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }

            // Extract name
            let name: Option<String> = entry
                .attr_value(gimli::DW_AT_name)
                .ok()
                .flatten()
                .and_then(|v| dwarf.attr_string(&unit, v).ok())
                .and_then(|s| s.to_string().ok().map(|s| s.to_string()));

            let name = match name {
                Some(n) => n,
                None => continue, // skip unnamed subprograms
            };

            // Extract low_pc (entry address)
            let low_pc: Option<u64> = entry
                .attr_value(gimli::DW_AT_low_pc)
                .ok()
                .flatten()
                .and_then(|v| match v {
                    gimli::AttributeValue::Addr(a) => Some(a),
                    _ => None,
                });

            let addr = match low_pc {
                Some(a) if a != 0 => a,
                _ => continue, // skip abstract/inlined subprograms
            };

            // Extract size from high_pc (may be an absolute address or an offset)
            let size: Option<u64> = entry
                .attr_value(gimli::DW_AT_high_pc)
                .ok()
                .flatten()
                .and_then(|v| match v {
                    gimli::AttributeValue::Addr(high) if high > addr => Some(high - addr),
                    gimli::AttributeValue::Udata(off) => Some(off),
                    _ => None,
                });

            funcs.push(DwarfFunction { name, addr, size });
        }
    }

    funcs.sort_by_key(|f| f.addr);
    Ok(funcs)
}
