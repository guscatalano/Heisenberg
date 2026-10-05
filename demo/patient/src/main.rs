//! Heisenberg demo "patient": a process that misbehaves deterministically so an
//! agent has something real to diagnose in a dump. Modes:
//!
//!   deadlock  (default) two threads acquire two Win32 CRITICAL_SECTIONs in the
//!             opposite order (classic AB-BA). Shows up cleanly under cdb's
//!             `!locks` / `!cs` and in the thread stacks as
//!             ntdll!RtlpWaitOnCriticalSection — exactly what analyze.deadlock
//!             looks for.
//!   crash     dereference a null pointer -> access violation (for the crash arc).
//!   heapbug [delay_ms]
//!             overflow a 32-byte heap buffer by writing well past its end. The
//!             contrast is the whole point of the page-heap demo:
//!               * WITHOUT page heap: the overflow lands in adjacent committed
//!                 heap, silently smashing neighbouring block headers; nothing
//!                 faults until the block is freed, where the heap manager trips
//!                 a STATUS_HEAP_CORRUPTION fast-fail deep in ntdll -- a crash
//!                 whose stack is far from the actual bug.
//!               * WITH Full Page Heap: a no-access guard page sits immediately
//!                 after the allocation, so the very first out-of-bounds store
//!                 faults on the spot, in patient's own code -- the dump points
//!                 straight at the overflow. `delay_ms` (default 6000) leaves
//!                 time to arm a crash trigger before the fault.
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
        "heapbug" => {
            use std::alloc::{alloc, dealloc, Layout};
            let delay_ms: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(6000);
            println!("patient pid {pid}: heap buffer overflow in {delay_ms}ms...");
            thread::sleep(Duration::from_millis(delay_ms));
            // Two 32-byte blocks on the process heap (Rust's System allocator ->
            // HeapAlloc, which Full Page Heap guards). Fresh same-size allocations
            // land next to each other, so overflowing `a` clobbers `b`'s header.
            let layout = Layout::from_size_align(32, 16).unwrap();
            unsafe {
                let a = alloc(layout);
                let b = alloc(layout);
                assert!(!a.is_null() && !b.is_null());
                // Write 512 bytes into the 32-byte buffer `a`. write_volatile keeps
                // the compiler from eliding the out-of-bounds stores.
                //  - Full Page Heap: the store just past offset ~32 hits a's guard
                //    page and faults HERE, in patient's own code (an access violation).
                //  - No page heap: these stores land in committed heap and smash b's
                //    block header without faulting...
                for i in 0..512usize {
                    std::ptr::write_volatile(a.add(i), 0x41u8);
                }
                // ...and the damage only surfaces now: freeing b validates its
                // (clobbered) header and trips a deterministic heap-corruption
                // fast-fail deep inside ntdll -- far from the real bug.
                dealloc(b, layout);
                dealloc(a, layout);
            }
            println!("patient pid {pid}: (never reached)");
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
