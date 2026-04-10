use std::cell::Cell;
use std::ffi::CStr;
use std::os::fd::RawFd;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use libc::{c_char, c_int, c_void};
use serde::Serialize;

type GetenvFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;

const TRACE_LOG_ENV: &[u8] = b"EXPLICIT_ENV_TRACE_LOG\0";
const GETENV_NAME: &[u8] = b"getenv\0";
#[cfg(target_os = "linux")]
const SECURE_GETENV_NAME: &[u8] = b"secure_getenv\0";
#[cfg(target_os = "linux")]
const ALT_SECURE_GETENV_NAME: &[u8] = b"__secure_getenv\0";

static REAL_GETENV: OnceLock<GetenvFn> = OnceLock::new();
#[cfg(target_os = "linux")]
static REAL_SECURE_GETENV: OnceLock<GetenvFn> = OnceLock::new();
#[cfg(target_os = "linux")]
static REAL_ALT_SECURE_GETENV: OnceLock<GetenvFn> = OnceLock::new();
static LOG_FD: OnceLock<Option<RawFd>> = OnceLock::new();

thread_local! {
    static IN_TRACE: Cell<bool> = const { Cell::new(false) };
}

#[derive(Serialize)]
struct EnvTraceEvent {
    ts_ms: i64,
    pid: i32,
    ppid: i32,
    operation: &'static str,
    key: String,
    found: bool,
    value: Option<String>,
    executable: Option<String>,
}

struct TraceGuard;

impl TraceGuard {
    fn enter() -> Option<Self> {
        IN_TRACE.with(|flag| if flag.replace(true) { None } else { Some(Self) })
    }
}

impl Drop for TraceGuard {
    fn drop(&mut self) {
        IN_TRACE.with(|flag| flag.set(false));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    unsafe { intercept_getenv(resolve_real_getenv(), "getenv", name) }
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    let real = resolve_real_secure_getenv().unwrap_or_else(resolve_real_getenv);
    unsafe { intercept_getenv(real, "secure_getenv", name) }
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __secure_getenv(name: *const c_char) -> *mut c_char {
    let real = resolve_real_alt_secure_getenv()
        .or_else(resolve_real_secure_getenv)
        .unwrap_or_else(resolve_real_getenv);
    unsafe { intercept_getenv(real, "__secure_getenv", name) }
}

unsafe fn intercept_getenv(
    real: GetenvFn,
    operation: &'static str,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() {
        return unsafe { real(name) };
    }

    let Some(_guard) = TraceGuard::enter() else {
        return unsafe { real(name) };
    };

    let value_ptr = unsafe { real(name) };
    write_event(operation, name, value_ptr);
    value_ptr
}

fn resolve_real_getenv() -> GetenvFn {
    *REAL_GETENV.get_or_init(|| unsafe { resolve_symbol(GETENV_NAME).unwrap_or(libc::getenv) })
}

#[cfg(target_os = "linux")]
fn resolve_real_secure_getenv() -> Option<GetenvFn> {
    REAL_SECURE_GETENV
        .get_or_init(|| unsafe { resolve_symbol(SECURE_GETENV_NAME) })
        .to_owned()
}

#[cfg(target_os = "linux")]
fn resolve_real_alt_secure_getenv() -> Option<GetenvFn> {
    REAL_ALT_SECURE_GETENV
        .get_or_init(|| unsafe { resolve_symbol(ALT_SECURE_GETENV_NAME) })
        .to_owned()
}

unsafe fn resolve_symbol(name: &[u8]) -> Option<GetenvFn> {
    let symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr().cast::<c_char>()) };
    if symbol.is_null() {
        return None;
    }
    Some(unsafe { std::mem::transmute::<*mut c_void, GetenvFn>(symbol) })
}

fn write_event(operation: &'static str, name: *const c_char, value_ptr: *mut c_char) {
    let Some(fd) = log_fd() else {
        return;
    };

    let key = unsafe { c_string_to_owned(name) };
    let value =
        (!value_ptr.is_null()).then(|| unsafe { c_string_to_owned(value_ptr.cast_const()) });
    let event = EnvTraceEvent {
        ts_ms: unix_millis(),
        pid: unsafe { libc::getpid() },
        ppid: unsafe { libc::getppid() },
        operation,
        key,
        found: !value_ptr.is_null(),
        value,
        executable: current_executable(),
    };

    if let Ok(mut line) = serde_json::to_vec(&event) {
        line.push(b'\n');
        unsafe {
            let _ = libc::write(fd, line.as_ptr().cast::<c_void>(), line.len());
        }
    }
}

fn log_fd() -> Option<RawFd> {
    *LOG_FD.get_or_init(|| {
        let real_getenv = resolve_real_getenv();
        let path_ptr = unsafe { real_getenv(TRACE_LOG_ENV.as_ptr().cast::<c_char>()) };
        if path_ptr.is_null() {
            return None;
        }

        let path = unsafe { c_string_to_owned(path_ptr.cast_const()) };
        let Some(c_path) = std::ffi::CString::new(path).ok() else {
            return None;
        };

        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_CREAT | libc::O_APPEND | libc::O_WRONLY,
                0o600 as c_int,
            )
        };
        (fd >= 0).then_some(fd)
    })
}

fn current_executable() -> Option<String> {
    std::env::current_exe()
        .ok()
        .map(|path| path.display().to_string())
}

unsafe fn c_string_to_owned(value: *const c_char) -> String {
    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_millis() as i64)
        .unwrap_or_default()
}
