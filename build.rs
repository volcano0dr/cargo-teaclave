use anyhow::{bail, Context, Result};
use std::env;
use std::fs;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() -> Result<()> {
    let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    run_vendor()?;
    build_edl(&sdk_dir)?;

    println!("cargo:rustc-link-search=native=./out");
    println!("cargo:rustc-link-lib=static=enclave_u");

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-lib=dylib=sgx_uprotected_fs");
    match is_sim.as_ref() {
        "SW" => {
            println!("cargo:rustc-link-lib=dylib=sgx_urts_sim");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service_sim");
        }
        _ => {
            println!("cargo:rustc-link-lib=dylib=sgx_urts");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
        }
    };
    Ok(())
}

fn build_edl(sdk_dir: &str) -> Result<()> {
    fs::create_dir_all("out").context("Failed to create out dir.")?;

    let sgx_sdk = PathBuf::from(sdk_dir);
    let edger8r = sgx_sdk.join("bin/x64/sgx_edger8r");
    run(Command::new(&edger8r)
        .arg("--untrusted")
        .arg("./src/enclave.edl")
        .arg("--search-path")
        .arg("./vendor/sgx_edl/edl")
        .arg("--search-path")
        .arg("./vendor/sgx_edl/edl/intel")
        .arg("--untrusted-dir")
        .arg("./out"))?;

    let mut build = cc::Build::new();
    build
        .opt_level(2)
        .flag("-fPIC")
        .flag("-Wno-attributes")
        .include("./vendor/sgx_edl/edl")
        .include("./vendor/sgx_edl/common/inc")
        .include(&sgx_sdk.join("include"))
        .include(&sgx_sdk.join("include/tlibc"))
        .include(&sgx_sdk.join("include/llibcxx"))
        .include(&sgx_sdk.join("include/ipp"))
        .out_dir("./out")
        .warnings(false)
        .file("./out/enclave_u.c")
        .cargo_metadata(false);

    build.compile("enclave_u");
    Ok(())
}

fn run_vendor() -> Result<()> {
    fs::create_dir_all("vendor").context("Failed to create vendor dir.")?;

    run(Command::new("cargo")
        .arg("vendor")
        .arg("./vendor")
        .stdout(Stdio::null())
        .stderr(Stdio::null()))
}

fn run(cmd: &mut Command) -> Result<()> {
    let output = match cmd.output() {
        Ok(output) => output,
        Err(e) => panic!("failed to execute command: {:?}\nerror: {}", cmd, e),
    };
    if !output.status.success() {
        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
        bail!(
            "\n\ncommand did not execute successfully: {:?}\n\
             expected success, got: {}\n\n",
            cmd,
            output.status
        );
    }
    Ok(())
}
