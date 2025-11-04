use clap::Parser;
use pathsearch::find_executable_in_path;
use std::ffi::CString;
use std::fs::canonicalize;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::landlock::install_filesystem_landlock_rules_on_current_thread;
use crate::landlock::install_network_seccomp_filter_on_current_thread;

#[derive(Debug, Parser)]
pub struct LandlockCommand {
    /// It is possible that the cwd used in the context of the sandbox policy
    /// is different from the cwd of the process to spawn.
    #[arg(long = "sandbox-policy-cwd")]
    pub sandbox_policy_cwd: PathBuf,

    #[arg(long = "sandbox-policy")]
    pub sandbox_policy: codex_core::protocol::SandboxPolicy,

    /// Full command args to run under landlock.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

pub fn run_main() -> ! {
    let LandlockCommand {
        sandbox_policy_cwd,
        sandbox_policy,
        command,
    } = LandlockCommand::parse();

    if command.is_empty() {
        panic!("No command specified to execute.");
    }

    if !sandbox_policy.has_full_network_access() {
        if let Err(e) = install_network_seccomp_filter_on_current_thread() {
            panic!("error adding seccomp filters: {e:?}");
        }
    }

    let writable_roots : Vec<PathBuf> = sandbox_policy
        .get_writable_roots_with_cwd(&sandbox_policy_cwd)
        .into_iter()
        .map(|writable_root| writable_root.root)
        .collect();

    static BWRAP_AVAILABLE: OnceLock<bool> = OnceLock::new();
    let bwrap_available = *BWRAP_AVAILABLE.get_or_init(|| { find_executable_in_path("bwrap").is_some() });

    let mut use_bwrap : bool = false;
    if !sandbox_policy.has_full_disk_write_access() {
        if let Err(e) = install_filesystem_landlock_rules_on_current_thread(&writable_roots) {
            if !bwrap_available {
                panic!("error adding landlock and bwrap isn't avialable as a fallback: {e:?}");
            }
            use_bwrap = true;
        }
    }

    // TODO(ragona): Add appropriate restrictions if
    // `sandbox_policy.has_full_disk_read_access()` is `false`.

    #[expect(clippy::expect_used)]
    let c_command =
        CString::new(command[0].as_str()).expect("Failed to convert command to CString");
    #[expect(clippy::expect_used)]
    let c_args: Vec<CString> = command
        .iter()
        .skip(1)
        .map(|arg| CString::new(arg.as_str()).expect("Failed to convert arg to CString"))
        .collect();

    // If we don't have full disk write access and landlock isn't available we run the command under bwrap with filesystem restrictions
    if use_bwrap {
        let mut args = vec![
            CString::new("--unshare-all").unwrap(),
            CString::new("--share-net").unwrap(),
            CString::new("--ro-bind").unwrap(),
            CString::new("/").unwrap(),
            CString::new("/").unwrap(),
            CString::new("--dev").unwrap(),
            CString::new("/dev").unwrap(),
        ];

        // Add --bind <path> <path> for the realpath of each writable root
        for root in &writable_roots {
            match canonicalize(&root) {
                Ok(canonical_root) => {
                    let canonical_root_str = canonical_root.to_string_lossy();
                    args.push(CString::new("--bind").unwrap());
                    args.push(CString::new(canonical_root_str.as_ref()).unwrap());
                    args.push(CString::new(canonical_root_str.as_ref()).unwrap());
                }
                Err(e) => {
                    panic!("error canonicalizing root {:?}: {}", root, e);
                }
            }
        }

        args.push(c_command);
        args.extend(c_args);

        let mut args_ptrs: Vec<*const libc::c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
        args_ptrs.push(std::ptr::null());

        let bwrap = CString::new("bwrap").expect("Failed to convert literal to CString");

        unsafe {
            libc::execvp(bwrap.as_ptr(), args_ptrs.as_ptr());
        }
    }
    else {
        let mut c_args_ptrs: Vec<*const libc::c_char> = c_args.iter().map(|arg| arg.as_ptr()).collect();
        c_args_ptrs.push(std::ptr::null());

        unsafe {
            libc::execvp(c_command.as_ptr(), c_args_ptrs.as_ptr());
        }
    }

    // If execvp returns, there was an error.
    let err = std::io::Error::last_os_error();
    panic!("Failed to execvp {}: {err}", command[0].as_str());
}
