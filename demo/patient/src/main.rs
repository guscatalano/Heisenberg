//! Heisenberg demo "patient": a process that misbehaves deterministically so an
//! agent has something real to diagnose in a dump. Modes:
//!
//!   deadlock  (default) two threads acquire two Win32 CRITICAL_SECTIONs in the
//!             opposite order (classic AB-BA). Shows up cleanly under cdb's
//!             `!locks` / `!cs` and in the thread stacks as
//!             ntdll!RtlpWaitOnCriticalSection — exactly what analyze.deadlock
//!             looks for.
//!   crash     dereference a null pointer -> access violation (for the crash arc).
//!
//! Zero dependencies: links the two CRITICAL_SECTION calls from kernel32 directly.

use std::thread;
use std::time::Duration;

// RTL_CRITICAL_SECTION is 0x28 (40) bytes on x64 and pointer-aligned.
#[repr(C)]
struct CriticalSection([usize; 5]);

#[link(name = "kernel32")]
extern "system" {
    fn InitializeCriticalSection(p: *mut CriticalSection);
    fn EnterCriticalSection(p: *mut CriticalSection);
}

/// A raw CRITICAL_SECTION pointer, leaked so it never moves (it stores
/// self-referential pointers) and is safe to share across threads.
#[derive(Clone, Copy)]
struct Lock(*mut CriticalSection);
unsafe impl Send for Lock {}
unsafe impl Sync for Lock {}

impl Lock {
    fn new() -> Lock {
        let p = Box::into_raw(Box::new(CriticalSection([0; 5])));
        unsafe { InitializeCriticalSection(p) };
        Lock(p)
    }
    fn enter(self) {
        unsafe { EnterCriticalSection(self.0) };
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "deadlock".to_string());
    let pid = std::process::id();

    match mode.as_str() {
        "crash" => {
            println!("patient pid {pid}: crashing (null dereference) in 1s...");
            thread::sleep(Duration::from_secs(1));
            // Deliberate access violation.
            let p: *mut u32 = std::ptr::null_mut();
            unsafe { p.write_volatile(0xdead) };
        }
        _ => {
            let lock_a = Lock::new();
            let lock_b = Lock::new();
            println!("patient pid {pid}: two worker threads, locks A and B");

            // Worker 1: holds A, then wants B.
            let t1 = thread::Builder::new()
                .name("worker-holds-A-wants-B".into())
                .spawn(move || {
                    lock_a.enter();
                    thread::sleep(Duration::from_millis(400)); // let worker 2 grab B
                    lock_b.enter(); // <- blocks forever: worker 2 holds B
                })
                .unwrap();

            // Worker 2: holds B, then wants A.
            let t2 = thread::Builder::new()
                .name("worker-holds-B-wants-A".into())
                .spawn(move || {
                    lock_b.enter();
                    thread::sleep(Duration::from_millis(400)); // let worker 1 grab A
                    lock_a.enter(); // <- blocks forever: worker 1 holds A
                })
                .unwrap();

            println!("patient pid {pid}: DEADLOCKED (AB-BA). Hanging; capture me.");
            let _ = t1.join();
            let _ = t2.join();
        }
    }
}
