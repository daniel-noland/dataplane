// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! RAII wrapper for [`JoinHandle`](tokio::task::JoinHandle) that aborts the
//! task on drop.  See [`AbortOnDrop`] for details.

use tokio::task::JoinHandle;

/// A [`JoinHandle`] wrapper that aborts the task when dropped.
///
/// During incremental construction of [`TestVm`](crate::vm::TestVm),
/// several background tasks are spawned across multiple phases.  If a
/// later phase fails, all previously spawned tasks must be aborted.
/// Without this wrapper, every early-return site must manually call
/// `.abort()` on the correct subset of handles -- a pattern that is
/// fragile and incorrect under panics.
///
/// `AbortOnDrop` solves this by aborting the inner task in its [`Drop`]
/// impl.  Once all phases succeed, the handles are extracted via
/// [`into_inner`](Self::into_inner) and moved into the fully-constructed
/// struct, disarming the automatic abort.
///
/// # Usage
///
/// ```ignore
/// let handle = AbortOnDrop::new(tokio::spawn(async { /* ... */ }));
///
/// // If this line returns Err, `handle` is dropped and the task is aborted.
/// some_fallible_operation().await?;
///
/// // On success, extract the inner handle to disarm the abort-on-drop.
/// let join_handle = handle.into_inner();
/// ```
#[derive(Debug)]
pub(crate) struct AbortOnDrop<T> {
    inner: Option<JoinHandle<T>>,
}

impl<T> AbortOnDrop<T> {
    /// Wraps an existing [`JoinHandle`], arming the abort-on-drop behavior.
    pub fn new(handle: JoinHandle<T>) -> Self {
        Self {
            inner: Some(handle),
        }
    }

    /// Spawns a new task and wraps the resulting handle.
    ///
    /// This is a convenience shorthand for `AbortOnDrop::new(tokio::spawn(fut))`.
    pub fn spawn(future: impl std::future::Future<Output = T> + Send + 'static) -> Self
    where
        T: Send + 'static,
    {
        Self::new(tokio::spawn(future))
    }

    /// Extracts the inner [`JoinHandle`], disarming the abort-on-drop behavior.
    ///
    /// After this call, the task will **not** be aborted when the wrapper is
    /// dropped (because the wrapper no longer owns the handle).
    ///
    /// # Panics
    ///
    /// Panics if called more than once (the handle has already been taken).
    pub fn into_inner(mut self) -> JoinHandle<T> {
        self.inner
            .take()
            .expect("AbortOnDrop::into_inner called after handle was already taken")
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.inner.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn into_inner_disarms_abort() {
        let completed = Arc::new(AtomicBool::new(false));
        let completed2 = completed.clone();

        let guard = AbortOnDrop::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            completed2.store(true, Ordering::SeqCst);
        });

        // Disarm -- the task should NOT be aborted.
        let handle = guard.into_inner();
        handle.await.expect("task should complete successfully");

        assert!(completed.load(Ordering::SeqCst), "task should have completed");
    }

    #[tokio::test]
    async fn drop_aborts_task() {
        let completed = Arc::new(AtomicBool::new(false));
        let completed2 = completed.clone();

        let guard = AbortOnDrop::spawn(async move {
            // Sleep long enough that the test has time to drop the guard.
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            completed2.store(true, Ordering::SeqCst);
        });

        // Drop the guard -- the task should be aborted.
        drop(guard);

        // Give the runtime a moment to process the abort.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        assert!(
            !completed.load(Ordering::SeqCst),
            "task should have been aborted, not completed"
        );
    }
}