//! Containment for panics raised inside third-party parsers.
//!
//! # Why this exists
//!
//! ADR-0006 requires strypt's own parsing code never to panic: malformed input is *expected*
//! input, and failures are typed `Result` values. That rule cannot be extended to a dependency
//! by wishing. `lopdf` is a third-party PDF parser handling attacker-controlled bytes
//! (ADR-0018), and `docs/THREAT_MODEL.md` §5.1 names a panic inside it as one of the realistic
//! residual risks that `forbid(unsafe_code)` does not address.
//!
//! That risk stopped being theoretical: a sustained fuzz run reached an integer overflow in
//! `lopdf` 0.44.0's cross-reference parser (`parser/mod.rs:516`, `start + index` where `start`
//! comes from the file). Because `Cargo.toml` deliberately enables `overflow-checks` in release
//! so that an overflow aborts rather than wrapping into a nonsensical offset, the shipped
//! binary panicked — a user handed a hostile PDF got a stack trace and exit code 101 instead of
//! "this file could not be processed".
//!
//! # What this does, and what it does not
//!
//! `guard` runs a closure and converts an unwinding panic into a typed error, so a dependency's
//! panic reaches the user as an ordinary refusal. **This is containment, not a fix.** The
//! defect stays in the dependency and is reported upstream; this only stops it reaching the
//! user as a crash.
//!
//! Three limits, stated because a guard that is trusted beyond its reach is worse than none:
//!
//! 1. **It requires unwinding panics.** Built with `panic = "abort"` the process dies before
//!    any of this runs. strypt does not set `panic = "abort"`, and this is a reason not to.
//! 2. **It cannot catch what does not unwind** — a stack overflow from deep recursion, an
//!    abort, or a SIGSEGV. Bounded recursion (`ParseLimits`) is the control for the first.
//! 3. **It says nothing about correctness.** A dependency that panicked may equally return a
//!    wrong answer without panicking, which no guard detects. Fail-closed refusal on panic is a
//!    floor, not a guarantee.
//!
//! # Why the panic message is suppressed
//!
//! The default panic hook prints to stderr. A panic message from a parser can quote the bytes
//! it was parsing, and those bytes are the user's document — the metadata they are trying to
//! destroy. CLAUDE.md §3.8 forbids printing metadata values, so a guarded panic must not print
//! the default message. The hook is installed once and delegates to the previous hook whenever
//! the guard is not active, so unguarded panics elsewhere still report normally.

use std::cell::Cell;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

thread_local! {
    /// True while a guarded call is on this thread's stack.
    static GUARDED: Cell<bool> = const { Cell::new(false) };
}

static HOOK: Once = Once::new();

/// Install a panic hook that stays silent for guarded calls and delegates otherwise.
///
/// Installed at most once per process. The flag is thread-local, so a guarded call on one
/// thread never silences a genuine panic on another.
fn install_hook() {
    HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if GUARDED.with(Cell::get) {
                // Deliberately silent: the caller turns this into a typed error, and the
                // message may contain fragments of the user's document.
                return;
            }
            previous(info);
        }));
    });
}

/// Run `f`, converting an unwinding panic into `on_panic()`.
///
/// # Errors
///
/// Returns whatever `f` returns on the ordinary path. If `f` panics and the panic unwinds,
/// returns `on_panic()` instead — so a caller can distinguish "this file was refused" from
/// "the parser fell over", which are different facts about the same input.
///
/// `AssertUnwindSafe` is used because the closure operates on values owned by the caller and
/// nothing observable is shared across the boundary: on the panic path the partially-built
/// value is dropped and an error is returned, so no caller can observe a half-updated state.
pub fn guard<T, E, F, P>(f: F, on_panic: P) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
    P: FnOnce() -> E,
{
    install_hook();

    let previous = GUARDED.replace(true);
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    GUARDED.set(previous);

    match result {
        Ok(value) => value,
        Err(_) => Err(on_panic()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::guard;

    #[derive(Debug, PartialEq)]
    struct Refused;

    #[test]
    fn a_panic_becomes_an_error() {
        let out: Result<u8, Refused> = guard(|| panic!("dependency exploded"), || Refused);
        assert_eq!(out, Err(Refused));
    }

    #[test]
    fn an_arithmetic_overflow_is_caught_like_any_other_panic() {
        // The shape of the real finding: lopdf's `start + index` with overflow-checks on.
        let out: Result<usize, Refused> = guard(
            || {
                // `black_box` because the compiler rejects a literal `usize::MAX + 1` outright
                // via the arithmetic_overflow lint. The real overflow comes from parsed input
                // the compiler cannot see, so hiding the value reproduces the real shape.
                let start = std::hint::black_box(usize::MAX);
                Ok(start + 1)
            },
            || Refused,
        );
        assert_eq!(out, Err(Refused));
    }

    #[test]
    fn a_success_passes_through_untouched() {
        let out: Result<u8, Refused> = guard(|| Ok(7), || Refused);
        assert_eq!(out, Ok(7));
    }

    #[test]
    fn an_ordinary_error_is_not_turned_into_a_panic_error() {
        // A guard that flattened every failure into "it panicked" would erase the distinction
        // between a refusal and a crash, which is the distinction the caller acts on.
        #[derive(Debug, PartialEq)]
        enum E {
            Normal,
            Panicked,
        }
        let out: Result<u8, E> = guard(|| Err(E::Normal), || E::Panicked);
        assert_eq!(out, Err(E::Normal));
    }

    #[test]
    fn the_guard_flag_is_cleared_afterwards() {
        // If the flag leaked, a later genuine panic on this thread would be silenced — the
        // guard would be suppressing exactly the reports it must not hide.
        let _: Result<u8, Refused> = guard(|| panic!("boom"), || Refused);
        super::GUARDED.with(|g| assert!(!g.get(), "guard flag leaked past the guarded call"));
    }
}
