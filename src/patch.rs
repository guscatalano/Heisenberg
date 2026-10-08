//! Byte patching: live-process memory (WriteProcessMemory) and on-disk PE files.
//! Every patch first reads back the original bytes so the change is reversible via
//! the ledger. Addresses for a module are given as RVAs (as a disassembler shows,
//! e.g. "patient+0x13a0"); `rva_to_file_offset` maps those to a file offset.

/// Parse "90 90 48 89" / "909048 89" / "0x90,0x90" into raw bytes.
pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',')
        .collect::<String>()
        .replace("0x", "")
        .replace("0X", "");
    if cleaned.is_empty() {
        return Err("no bytes given".to_string());
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!("hex has an odd number of digits ({})", cleaned.len()));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| format!("bad hex at '{}'", &cleaned[i..i + 2])))
        .collect()
}

/// Map a module-relative virtual address (RVA) to a file offset by parsing the
/// PE section table. Returns None if the RVA isn't inside any section.
pub fn rva_to_file_offset(pe: &[u8], rva: u64) -> Option<u64> {
    let rd16 = |o: usize| -> Option<u16> { pe.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]])) };
    let rd32 = |o: usize| -> Option<u32> { pe.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])) };
    if pe.len() < 0x40 {
        return None;
    }
    let e_lfanew = rd32(0x3c)? as usize;
    if pe.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let num_sections = rd16(coff + 2)? as usize;
    let opt_size = rd16(coff + 16)? as usize;
    let sect = coff + 20 + opt_size;
    for i in 0..num_sections {
        let s = sect + i * 40;
        let vaddr = rd32(s + 12)? as u64;
        let vsize = rd32(s + 8)? as u64;
        let rawptr = rd32(s + 20)? as u64;
        let rawsize = rd32(s + 16)? as u64;
        let span = vsize.max(rawsize);
        if rva >= vaddr && rva < vaddr + span {
            let off = rawptr + (rva - vaddr);
            if off < pe.len() as u64 {
                return Some(off);
            }
        }
    }
    None
}

/// Read `len` bytes from a live process at `address`. Needs appropriate rights.
#[cfg(windows)]
pub fn read_process_memory(pid: u32, address: u64, len: usize) -> std::io::Result<Vec<u8>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    unsafe {
        let h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("OpenProcess: {e}")))?;
        let mut buf = vec![0u8; len];
        let mut read = 0usize;
        let r = ReadProcessMemory(h, address as *const core::ffi::c_void, buf.as_mut_ptr() as *mut core::ffi::c_void, len, Some(&mut read));
        let _ = CloseHandle(h);
        r.map_err(|e| std::io::Error::other(format!("ReadProcessMemory: {e}")))?;
        buf.truncate(read);
        Ok(buf)
    }
}

/// Write `bytes` into a live process at `address`, making the region temporarily
/// writable and flushing the instruction cache. Returns the original bytes.
#[cfg(windows)]
pub fn write_process_memory(pid: u32, address: u64, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE};
    unsafe {
        let h = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            false,
            pid,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("OpenProcess: {e}")))?;
        let addr = address as *const core::ffi::c_void;
        // original bytes (for revert)
        let mut orig = vec![0u8; bytes.len()];
        let mut got = 0usize;
        if ReadProcessMemory(h, addr, orig.as_mut_ptr() as *mut core::ffi::c_void, bytes.len(), Some(&mut got)).is_err() || got != bytes.len() {
            let _ = CloseHandle(h);
            return Err(std::io::Error::other("could not read original bytes"));
        }
        let mut old = PAGE_PROTECTION_FLAGS(0);
        if VirtualProtectEx(h, addr, bytes.len(), PAGE_EXECUTE_READWRITE, &mut old).is_err() {
            let _ = CloseHandle(h);
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "VirtualProtectEx failed"));
        }
        let mut written = 0usize;
        let w = WriteProcessMemory(h, addr, bytes.as_ptr() as *const core::ffi::c_void, bytes.len(), Some(&mut written));
        let mut tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(h, addr, bytes.len(), old, &mut tmp);
        let _ = FlushInstructionCache(h, Some(addr), bytes.len());
        let _ = CloseHandle(h);
        w.map_err(|e| std::io::Error::other(format!("WriteProcessMemory: {e}")))?;
        if written != bytes.len() {
            return Err(std::io::Error::other(format!("partial write {written}/{}", bytes.len())));
        }
        Ok(orig)
    }
}

/// Patch `bytes` into a file at `file_offset`, returning the original bytes there.
pub fn patch_file(path: &std::path::Path, file_offset: u64, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    f.seek(SeekFrom::Start(file_offset))?;
    let mut orig = vec![0u8; bytes.len()];
    f.read_exact(&mut orig)?;
    f.seek(SeekFrom::Start(file_offset))?;
    f.write_all(bytes)?;
    f.flush()?;
    Ok(orig)
}

#[cfg(not(windows))]
pub fn read_process_memory(_pid: u32, _address: u64, _len: usize) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "windows only"))
}
#[cfg(not(windows))]
pub fn write_process_memory(_pid: u32, _address: u64, _bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "windows only"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_in_several_forms() {
        assert_eq!(parse_hex_bytes("90 90 90").unwrap(), vec![0x90, 0x90, 0x90]);
        assert_eq!(parse_hex_bytes("4889c8").unwrap(), vec![0x48, 0x89, 0xc8]);
        assert_eq!(parse_hex_bytes("0x48,0x89").unwrap(), vec![0x48, 0x89]);
        assert!(parse_hex_bytes("").is_err());
        assert!(parse_hex_bytes("abc").is_err());
        assert!(parse_hex_bytes("zz").is_err());
    }

    #[test]
    fn maps_rva_with_a_minimal_pe() {
        // Hand-build a tiny PE: DOS stub -> PE sig -> COFF(1 section, opt size 0)
        // -> one section ".text" VA 0x1000 vsize 0x2000 rawptr 0x400 rawsize 0x800.
        let mut pe = vec![0u8; 0x1000];
        pe[0..2].copy_from_slice(b"MZ");
        let e_lfanew: u32 = 0x80;
        pe[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let coff = e_lfanew as usize;
        pe[coff..coff + 4].copy_from_slice(b"PE\0\0");
        pe[coff + 4 + 2..coff + 4 + 4].copy_from_slice(&1u16.to_le_bytes()); // num sections
        pe[coff + 4 + 16..coff + 4 + 18].copy_from_slice(&0u16.to_le_bytes()); // opt header size
        let s = coff + 4 + 20;
        pe[s + 8..s + 12].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualSize
        pe[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        pe[s + 16..s + 20].copy_from_slice(&0x800u32.to_le_bytes()); // SizeOfRawData
        pe[s + 20..s + 24].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        // RVA 0x13a0 -> file 0x400 + (0x13a0 - 0x1000) = 0x7a0
        assert_eq!(rva_to_file_offset(&pe, 0x13a0), Some(0x7a0));
        assert_eq!(rva_to_file_offset(&pe, 0x9000), None); // outside any section
    }
}
