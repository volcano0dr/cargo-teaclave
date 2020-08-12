use crate::NativeTest;
use crate::TestOpt;
use anyhow::{bail, Result};
use sgx_types::*;
use sgx_urts::SgxEnclave;


static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern "C" {
    fn ecall_run_tests(eid: sgx_enclave_id_t) -> sgx_status_t;
}

fn init_enclave(native: &NativeTest, _cmd: &TestOpt) -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    let debug = 1;

    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        &native.test_out_dir.join(ENCLAVE_FILE),
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

pub(crate) fn run_test(native: &NativeTest, _cmd: &TestOpt) -> Result<()> {
    let enclave = match init_enclave(native, _cmd) {
        Ok(r) => {
            println!("Init enclave successful {}!", r.geteid());
            r
        }
        Err(x) => {
            bail!("Failed to create enclave {}.", x.as_str());
        }
    };

    let result = unsafe { ecall_run_tests(enclave.geteid()) };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            bail!("Failed to ECALL enclave {}.", result.as_str());
        }
    }

    enclave.destroy();
    Ok(())
}
