//! Wait Chain Traversal (WCT): the OS view of what each live thread is blocked on and who
//! holds it — ACROSS processes. This is what finds GUI hangs and cross-process deadlocks
//! that a single process's `!locks` can't see. Thin wrapper over the WCT API (advapi32).

#[cfg(windows)]
pub fn wait_chains(pid: u32) -> Result<serde_json::Value, String> {
    use serde_json::json;
    use windows::Win32::Foundation::CloseHandle;
    use windows::core::BOOL;
    use windows::Win32::System::Diagnostics::Debug::{
        CloseThreadWaitChainSession, GetThreadWaitChain, OPEN_THREAD_WAIT_CHAIN_SESSION_FLAGS,
        OpenThreadWaitChainSession, WAITCHAIN_NODE_INFO, WAIT_CHAIN_THREAD_OPTIONS,
        WCT_MAX_NODE_COUNT, WCT_OUT_OF_PROC_COM_FLAG, WCT_OUT_OF_PROC_CS_FLAG, WCT_OUT_OF_PROC_FLAG,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };

    unsafe {
        // 1) enumerate the thread ids owned by this pid.
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).map_err(|e| e.to_string())?;
        let mut tids: Vec<u32> = Vec::new();
        let mut te = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        if Thread32First(snap, &mut te).is_ok() {
            loop {
                if te.th32OwnerProcessID == pid {
                    tids.push(te.th32ThreadID);
                }
                te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snap, &mut te).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        if tids.is_empty() {
            return Err(format!("no threads found for pid {pid} (does it exist? cross-user/elevated targets need SeDebug)"));
        }

        // 2) open a synchronous WCT session (flags 0 = blocking/synchronous).
        let session = OpenThreadWaitChainSession(OPEN_THREAD_WAIT_CHAIN_SESSION_FLAGS(0), None);
        // follow chains out of this process: COM, ALPC, and critical sections across processes.
        let flags = WAIT_CHAIN_THREAD_OPTIONS(
            WCT_OUT_OF_PROC_FLAG.0 | WCT_OUT_OF_PROC_COM_FLAG.0 | WCT_OUT_OF_PROC_CS_FLAG.0,
        );

        // 3) walk each thread's wait chain.
        let mut threads = Vec::new();
        let mut any_deadlock = false;
        for tid in tids {
            let mut nodes = [WAITCHAIN_NODE_INFO::default(); WCT_MAX_NODE_COUNT as usize];
            let mut count: u32 = WCT_MAX_NODE_COUNT;
            let mut is_cycle = BOOL(0);
            let ok = GetThreadWaitChain(
                session,
                None,
                flags,
                tid,
                &mut count,
                nodes.as_mut_ptr(),
                &mut is_cycle,
            );
            if ok.is_ok() && count > 0 {
                let is_cycle = is_cycle.as_bool();
                let mut chain = Vec::new();
                for n in nodes.iter().take(count as usize) {
                    let otype = n.ObjectType.0;
                    let ostatus = n.ObjectStatus.0;
                    // WctThreadType == 8: the node describes a thread (who is blocking/blocked).
                    let entry = if otype == 8 {
                        let t = n.Anonymous.ThreadObject;
                        json!({ "kind": "thread", "objectType": otype, "status": ostatus, "processId": t.ProcessId, "threadId": t.ThreadId, "waitTimeMs": t.WaitTime, "contextSwitches": t.ContextSwitches })
                    } else {
                        let l = n.Anonymous.LockObject;
                        let end = l.ObjectName.iter().position(|&c| c == 0).unwrap_or(l.ObjectName.len());
                        let name = String::from_utf16_lossy(&l.ObjectName[..end]);
                        json!({ "kind": "lock", "objectType": otype, "status": ostatus, "objectName": name })
                    };
                    chain.push(entry);
                }
                if is_cycle {
                    any_deadlock = true;
                }
                threads.push(json!({ "threadId": tid, "isDeadlockCycle": is_cycle, "nodeCount": count, "chain": chain }));
            }
        }
        CloseThreadWaitChainSession(session);
        Ok(json!({ "pid": pid, "deadlockDetected": any_deadlock, "threadsWithChains": threads.len(), "threads": threads }))
    }
}

#[cfg(not(windows))]
pub fn wait_chains(_pid: u32) -> Result<serde_json::Value, String> {
    Err("Wait Chain Traversal is Windows-only".to_string())
}
