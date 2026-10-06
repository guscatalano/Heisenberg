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
//!   deadheap  the "live capture, then harden" demo: two worker threads deadlock
//!             AB-BA (so the process HANGS and is alive to be captured), and the
//!             main thread then overflows a 32-byte heap buffer and parks.
//!               * WITHOUT page heap: the overflow is silent, so the process just
//!                 hangs -- a live dump shows the AB-BA deadlock cleanly, but the
//!                 heap damage has no visible culprit (the store already ran).
//!               * WITH Full Page Heap: the overflow faults IMMEDIATELY at the
//!                 out-of-bounds store, in patient's own code (a clean access
//!                 violation at the overflow) -- so after enabling page heap and
//!                 relaunching, the dump points straight at the faulty code. The
//!                 overflow runs only after the workers have deadlocked, so with
//!                 no page heap the process reliably reaches the hang.
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
            // A 32-byte heap block (Rust's System allocator -> HeapAlloc, which Full
            // Page Heap guards). The two bugs are arranged so each environment hits a
            // *deterministic* fault that tells the demo's story:
            //   * Full Page Heap: a guard page sits right after the block, so the
            //     first out-of-bounds store below faults IMMEDIATELY, in patient's
            //     own code (a clean access violation at the overflow).
            //   * No page heap: the small overflow lands in committed heap and does
            //     NOT fault, so execution reaches the double free, where the NT heap
            //     deterministically trips a STATUS_HEAP_CORRUPTION fast-fail deep
            //     inside ntdll -- a crash whose stack is the heap manager, not the
            //     code at fault.
            let layout = Layout::from_size_align(32, 16).unwrap();
            unsafe {
                let p = alloc(layout);
                assert!(!p.is_null());
                // overflow by 64 bytes; write_volatile keeps the stores from being elided
                for i in 0..64usize {
                    std::ptr::write_volatile(p.add(i), 0x41u8); // PAGE HEAP faults here
                }
                dealloc(p, layout);
                dealloc(p, layout); // NO page heap trips STATUS_HEAP_CORRUPTION here
            }
            println!("patient pid {pid}: (never reached)");
        }
        "deadheap" => {
            use std::alloc::{alloc, Layout};
            let lock_a = Lock::new();
            let lock_b = Lock::new();
            println!("patient pid {pid}: deadheap -- two worker threads, locks A and B");

            // Worker 1: holds A, then wants B.
            thread::Builder::new()
                .name("worker-holds-A-wants-B".into())
                .spawn(move || {
                    lock_a.enter();
                    thread::sleep(Duration::from_millis(400));
                    lock_b.enter(); // blocks forever: worker 2 holds B
                })
                .unwrap();
            // Worker 2: holds B, then wants A.
            thread::Builder::new()
                .name("worker-holds-B-wants-A".into())
                .spawn(move || {
                    lock_b.enter();
                    thread::sleep(Duration::from_millis(400));
                    lock_a.enter(); // blocks forever: worker 1 holds A
                })
                .unwrap();

            // Let the two workers reach the AB-BA deadlock before we touch the heap,
            // so with no page heap the overflow is silent and the process reliably
            // hangs (alive, capturable). With Full Page Heap the store below faults
            // immediately in patient's own code.
            thread::sleep(Duration::from_millis(900));
            println!("patient pid {pid}: DEADLOCKED (AB-BA); overflowing heap buffer...");
            let layout = Layout::from_size_align(32, 16).unwrap();
            unsafe {
                let p = alloc(layout);
                assert!(!p.is_null());
                for i in 0..64usize {
                    std::ptr::write_volatile(p.add(i), 0x41u8); // PAGE HEAP faults here
                }
                // No free: with no page heap the damage is silent, so the process
                // stays hung (below) instead of crashing. Deliberately leaked.
            }
            println!("patient pid {pid}: heap overflowed; hanging. Capture me.");
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
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
