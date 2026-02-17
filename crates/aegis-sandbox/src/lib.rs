//! OS-level sandboxing backends for Aegis.
//!
//! Provides [`SandboxBackend`] trait with two implementations:
//! - [`SeatbeltBackend`]: macOS Seatbelt (`sandbox-exec`) with auto-generated SBPL profiles
//! - [`ProcessBackend`]: simple process execution without OS-level isolation

pub mod backend;
#[cfg(target_os = "macos")]
pub mod compiler;
pub mod process;
#[cfg(target_os = "macos")]
pub mod profile;
#[cfg(target_os = "macos")]
pub mod seatbelt;

pub use backend::SandboxBackend;
pub use process::ProcessBackend;
#[cfg(target_os = "macos")]
pub use compiler::compile_cedar_to_sbpl;
#[cfg(target_os = "macos")]
pub use profile::generate_seatbelt_profile;
#[cfg(target_os = "macos")]
pub use seatbelt::SeatbeltBackend;

/// System paths that sandboxed processes need read access to for basic operation.
///
/// On macOS, even simple commands require access to the dyld shared cache,
/// system libraries, and various configuration paths. This constant is shared
/// between the Cedar-to-SBPL compiler and the Seatbelt profile generator.
#[cfg(target_os = "macos")]
pub(crate) const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/Library",
    "/System",
    "/private/var/db",
    "/private/etc",
    "/private/var/folders",
    "/dev",
];
