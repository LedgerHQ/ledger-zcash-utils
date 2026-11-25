//! The process-wide async runtime of the binding.
//!
//! Foreign callers have no ambient runtime, so the binding owns one. It is
//! created on first use and lives for the rest of the process.
//!
//! - **Shared and multi-threaded.** A scan is a task spawned on this runtime and
//!   cancelled by aborting it, which is how the Node binding cancels
//!   (`TransactionStream.cancel` aborts the spawned task). Blocking calls (chain
//!   tip, block height, transaction details) enter through [`block_on`] from the
//!   caller's thread, and a multi-thread runtime accepts that from several
//!   threads at once. A scan in flight therefore blocks no other call.
//! - **Few threads.** The CPU-heavy trial decryption leaves the async side
//!   through `spawn_blocking` into Rayon (`zcash_sync::sync`), so the workers
//!   only drive network I/O. The blocking pool is bounded at 4 to suit a handset.
//! - **Never panics on start-up.** A runtime that cannot be built is reported to
//!   every caller as an engine error.
//!
//! [`block_on`] must not be called from a runtime thread. The C ABI and JNI are
//! entered from foreign threads, so that cannot happen through them.

use std::future::Future;
use std::sync::OnceLock;
use tokio::runtime::{Builder, Runtime};

use crate::{Failure, ZCASH_ERR_ENGINE};

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();

fn build() -> Result<Runtime, String> {
    Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_name("zcash-ffi")
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

/// The shared runtime, built on first use.
pub(crate) fn runtime() -> Result<&'static Runtime, Failure> {
    RUNTIME.get_or_init(build).as_ref().map_err(|e| {
        (
            ZCASH_ERR_ENGINE,
            format!("could not start the runtime: {e}"),
        )
    })
}

/// Run a future to completion on the shared runtime, blocking the caller.
pub(crate) fn block_on<F: Future>(future: F) -> Result<F::Output, Failure> {
    Ok(runtime()?.block_on(future))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_on_returns_the_future_output() {
        assert_eq!(block_on(async { 21 * 2 }).unwrap(), 42);
    }

    #[test]
    fn runtime_is_shared_across_calls_and_threads() {
        let first = runtime().unwrap() as *const Runtime;
        let from_thread = std::thread::spawn(|| runtime().unwrap() as *const Runtime as usize)
            .join()
            .unwrap();
        assert_eq!(first as usize, from_thread);
    }

    #[test]
    fn several_threads_can_block_on_it_at_once() {
        let handles: Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    block_on(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        i
                    })
                    .unwrap()
                })
            })
            .collect();
        let mut got: Vec<i32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        got.sort();
        assert_eq!(got, (0..8).collect::<Vec<_>>());
    }
}
