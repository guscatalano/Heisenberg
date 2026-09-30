//! Kernel-debug setup helpers: crash-dump mode mapping, hypervisor detection, and
//! host-side transport guidance for serial and network (KDNET) kernel debugging
//! across Hyper-V, Proxmox/KVM, VMware, and physical targets.

use serde_json::{json, Value};

/// Map a friendly crash-dump mode to its `CrashDumpEnabled` value.
pub fn crash_dump_mode_value(mode: &str) -> Option<u32> {
    match mode.to_ascii_lowercase().as_str() {
        "none" | "disabled" | "off" => Some(0),
        "complete" | "full" => Some(1),
        "kernel" => Some(2),
        "small" | "minidump" => Some(3),
        "automatic" | "auto" => Some(7),
        _ => None,
    }
}

pub fn crash_dump_mode_name(v: u32) -> &'static str {
    match v {
        0 => "none",
        1 => "complete",
        2 => "kernel",
        3 => "small",
        7 => "automatic",
        _ => "unknown",
    }
}

/// Best-effort hypervisor/platform detection from the BIOS strings.
#[cfg(windows)]
pub fn detect_hypervisor() -> String {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let bios = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"HARDWARE\DESCRIPTION\System\BIOS");
    let get = |name: &str| -> String {
        bios.as_ref()
            .ok()
            .and_then(|k| k.get_value::<String, _>(name).ok())
            .unwrap_or_default()
    };
    let s = format!("{} {}", get("SystemManufacturer"), get("SystemProductName")).to_lowercase();
    if s.contains("qemu") || s.contains("kvm") {
        "proxmox/kvm".to_string()
    } else if s.contains("microsoft") && s.contains("virtual") {
        "hyper-v".to_string()
    } else if s.contains("vmware") {
        "vmware".to_string()
    } else if s.contains("virtualbox") || s.contains("innotek") {
        "virtualbox".to_string()
    } else {
        "physical/unknown".to_string()
    }
}

#[cfg(not(windows))]
pub fn detect_hypervisor() -> String {
    "non-windows".to_string()
}

/// Normalize a caller-supplied `host` hint, or "auto" → detected.
pub fn resolve_host(hint: Option<&str>) -> String {
    match hint.map(|h| h.to_ascii_lowercase()) {
        Some(h) if h != "auto" && !h.is_empty() => h,
        _ => detect_hypervisor(),
    }
}

const COMMON_CAVEATS: &[&str] = &[
    "Secure Boot must be OFF for kernel debugging; suspend BitLocker on the system volume first",
    "Reboot the target after bcdedit for the change to take effect",
    "test-signing / nointegritychecks are only for loading unsigned drivers — not needed for KD",
];

/// Host-side wiring + connect string for serial kernel debugging.
pub fn serial_guidance(host: &str, port: u32, baud: u32) -> Value {
    let h = host.to_lowercase();
    let (steps, connect): (Vec<String>, String) = if h.contains("proxmox") || h.contains("kvm") {
        (
            vec![
                "Proxmox host: `qm set <vmid> -serial0 socket` (serial0 = guest COM1); reboot the VM".into(),
                "That creates /var/run/qemu-server/<vmid>.serial0 — a UNIX socket, NOT a Windows named pipe".into(),
                "Preferred: run WinDbg in a 2nd Windows VM (its own `-serial0 socket`), then on the host: `socat UNIX-CONNECT:/var/run/qemu-server/<target>.serial0 UNIX-CONNECT:/var/run/qemu-server/<dbg>.serial0`".into(),
                "Or expose TCP via `args: -chardev socket,id=kd,host=0.0.0.0,port=4445,server=on,wait=off -device isa-serial,chardev=kd` and bridge TCP→named pipe on the debugger host".into(),
            ],
            format!("debugger VM: `windbg -k com:port=COM{port},baud={baud}` (or `com:pipe,port=\\\\.\\pipe\\<name>,resets=0,reconnect` after a TCP→pipe bridge)"),
        )
    } else if h.contains("hyper") {
        (
            vec![
                format!("Hyper-V host (elevated PowerShell): `Set-VMComPort -VMName <vm> {port} \\\\.\\pipe\\<PipeName>`"),
                "Hyper-V exposes the COM port directly as a Windows named pipe on the host — no socat/bridge needed".into(),
                "Gen2 VM: disable Secure Boot (Set-VMFirmware -EnableSecureBoot Off)".into(),
            ],
            format!("Hyper-V host: `windbg -k com:pipe,port=\\\\.\\pipe\\<PipeName>,resets=0,reconnect` (baud {baud})"),
        )
    } else if h.contains("vmware") {
        (
            vec!["VMware: add a serial port → named pipe `\\\\.\\pipe\\<name>`, 'This end is the server', 'The other end is an application'".into()],
            format!("`windbg -k com:pipe,port=\\\\.\\pipe\\<name>,resets=0,reconnect` (baud {baud})"),
        )
    } else {
        (
            vec!["Physical: connect a null-modem cable between the target and host COM ports".into()],
            format!("`windbg -k com:port=COM{port},baud={baud}`"),
        )
    };

    json!({
        "transport": "serial",
        "hypervisor": host,
        "guest": { "debugport": port, "baudrate": baud },
        "hostSteps": steps,
        "connect": connect,
        "caveats": COMMON_CAVEATS,
    })
}

/// Host-side wiring + connect string for network (KDNET) kernel debugging.
pub fn net_guidance(host: &str, hostip: &str, port: u32, key: Option<&str>) -> Value {
    let h = host.to_lowercase();
    let mut caveats: Vec<String> = vec![
        "KDNET NIC must be Microsoft-verified: e1000e (8086:10D3) or e1000 — NOT virtio".into(),
    ];
    caveats.extend(COMMON_CAVEATS.iter().map(|s| s.to_string()));

    let mut steps: Vec<String> = Vec::new();
    if h.contains("proxmox") || h.contains("kvm") {
        steps.push("Proxmox: `qm set <vmid> -net0 e1000e,bridge=vmbr0` (virtio is unsupported for KDNET)".into());
        steps.push("Proxmox+KVM: add a Hyper-V vendor id or Windows emits ZERO KDNET packets: `cpu: x86-64-v2-AES,hv-vendor-id=KVMKVMKVM` in the VM conf".into());
        caveats.push("Editing CPU/hardware in the Proxmox GUI strips the inline hv-vendor-id flag — reapply after any GUI change".into());
        caveats.push("Verify with tcpdump on the bridge: zero packets = hypervisor detection, not a firewall".into());
    } else if h.contains("hyper") {
        steps.push("Hyper-V Gen2: attach a synthetic NIC to an External (or Default) switch; KDNET over Hyper-V is supported".into());
        steps.push("Allow the KDNET UDP port through the Hyper-V host firewall".into());
    } else if h.contains("vmware") {
        steps.push("VMware: use e1000e; vmxnet3 is also KDNET-listed on recent Windows".into());
    } else {
        steps.push("Run `kdnet.exe` on the target to confirm the NIC is on the KDNET supported list".into());
    }

    let keytext = key.map(|k| k.to_string()).unwrap_or_else(|| "<auto-generated by bcdedit>".to_string());
    json!({
        "transport": "net",
        "hypervisor": host,
        "guest": { "hostip": hostip, "port": port, "key": keytext },
        "hostSteps": steps,
        "connect": format!("host: `windbg -k net:port={port},key={keytext}`  (-d to break in early)"),
        "caveats": caveats,
    })
}
