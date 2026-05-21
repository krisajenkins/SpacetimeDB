use tracing::Span;

/// Ergonomic wrapper for `tokio::task::spawn_blocking(f).await`.
///
/// If `f` panics, it will be bubbled up to the calling task.
pub async fn asyncify<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    // Ensure that `f` executes in the current span context.
    // If there is no current span, or it is disabled, `span` is disabled.
    let span = Span::current();
    tokio::task::spawn_blocking(move || {
        let _enter = span.enter();
        f()
    })
    .await
    .unwrap_or_else(|e| match e.try_into_panic() {
        Ok(panic_payload) => std::panic::resume_unwind(panic_payload),
        // the only other variant is cancelled, which shouldn't happen because we don't cancel it.
        Err(e) => panic!("Unexpected JoinError: {e}"),
    })
}
