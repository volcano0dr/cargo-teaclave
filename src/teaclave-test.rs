#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#![feature(core_intrinsics)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use std::alloc;
#[cfg(feature = "backtrace")]
use std::backtrace::{self, PrintFormat};
#[cfg(feature = "backtrace")]
use std::enclave;
use std::panic;
use sgx_signal::ContinueType;
use sgx_signal::exception;

#[no_mangle]
pub extern "C" fn ecall_run_tests() {

    #[cfg(feature = "backtrace")]
    {
        let enclave_path = match enclave::get_enclave_path() {
            Some(path) => path,
            None => {
                println!("Failed to get enclave path.");
                return;
            }
        };

        let ret = backtrace::enable_backtrace(&enclave_path, PrintFormat::Full);
        if ret.is_err() {
            println!("Failed to enable backtrace: {:?}", ret.unwrap_err());
            return;
        }
    }
    
    alloc::set_alloc_error_hook(|layout| {
        println!("memory allocation of {} bytes failed", layout.size());
        unsafe { std::intrinsics::abort() };
    });

    let _h = exception::register_exception(true, move |_| ContinueType::Search);

    panic::catch_unwind(|| {
        wheel::test::run_tests()
    }).ok();
}
