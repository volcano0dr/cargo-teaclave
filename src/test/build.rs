//#![allow(unused_imports)]

use crate::TestOpt;
use crate::NativeTest;
use crate::utils::{run, up_to_date};
use crate::utils::ENCLAVE_LDS;
use anyhow::{anyhow, bail, Context, Result};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

static TEST_ENCLAVE_LIB: &str = include_str!("../teaclave-test.rs");
static TEST_ENCLAVE_MANIFEST: &str = include_str!("../teaclave-test.toml");
static ENCLAVE_EDL: &str = include_str!("../enclave.edl");
static ENCLAVE_KEY: &str = include_str!("../enclave.private.pem");
static VENDOR_CONFIG: &str = include_str!("../vendor.config");


pub(crate) fn build_test(native: &NativeTest, cmd: &TestOpt) -> Result<()> {
    fs::create_dir_all(&native.test_out_dir).context("Failed to create test out dir.")?;

    let (package_name, crate_name) = get_rust_metadata().context("Failed to get metadata.")?;
    write_enclave_source(native, cmd, &package_name, &crate_name)?;
    run_vendor(native)?;
    build_edl(native)?;
    build_rust_enclave(native, cmd)?;
    link_enclave(native)?;
    sign_enclave(native)?;
    Ok(())
}

fn build_edl(native: &NativeTest) -> Result<()> {
    let edger8r = native.sdk_dir.join("bin/x64/sgx_edger8r");
    let ret = run(Command::new(&edger8r)
        .arg("--trusted")
        .arg(&native.test_dir.join("enclave.edl"))
        .arg("--search-path")
        .arg(&native.test_vendor_dir.join("sgx_edl/edl"))
        .arg("--search-path")
        .arg(&native.test_vendor_dir.join("sgx_edl/edl/intel"))
        .arg("--trusted-dir")
        .arg(&native.test_out_dir));
    if !ret {
        bail!("Failed to run sgx_edger8r.");
    }

    let edl_name = PathBuf::from("enclave.edl");
    let edl_name = edl_name.file_stem().context("EDL file name is invalid.")?;
    let mut lib_name = edl_name.to_os_string();
    lib_name.push("_t");
    let mut t_c = PathBuf::from(&lib_name);
    let mut t_h = PathBuf::from(&lib_name);
    t_c.set_extension("c");
    t_h.set_extension("h");

    println!("GEN  => {} {}", &t_c.display(), &t_h.display());

    let mut build = cc::Build::new();
    build
        .target("x86_64-unknown-linux-gnu")
        .host("x86_64-unknown-linux-gnu")
        .opt_level(2)
        .no_default_flags(true)
        .flag("-m64")
        .flag("-O2")
        .flag("-fstack-protector")
        .flag("-ffreestanding")
        .flag("-nostdinc")
        .flag("-fvisibility=hidden")
        .flag("-fpie")
        .flag("-fno-strict-overflow")
        .flag("-fno-delete-null-pointer-checks")
        .include("./")
        .include("./include")
        .include(&native.test_vendor_dir.join("sgx_edl/edl"))
        .include(&native.test_vendor_dir.join("sgx_edl/common/inc"))
        .include(&native.sdk_dir.join("include"))
        .include(&native.sdk_dir.join("include/tlibc"))
        .include(&native.sdk_dir.join("include/llibcxx"))
        .include(&native.sdk_dir.join("include/ipp"))
        .out_dir(&native.test_out_dir)
        .warnings(false)
        .file(&native.test_out_dir.join(&t_c))
        .cargo_metadata(false);

    let mitigation_cflags1 = "-mindirect-branch-register";
    let mitigation_cflags2 = "-mfunction-return=thunk-extern";
    let mitigation_asflags = "-fno-plt";
    let mitigation_loadflags1 = "-Wa,-mlfence-after-load=yes";
    let mitigation_loadflags2 = "-Wa,-mlfence-before-ret=not";
    let mitigation_cfflags1 = "-Wa,-mlfence-before-indirect-branch=register";
    let mitigation_cfflags2 = "-Wa,-mlfence-before-ret=not";
    let mitigation = env::var("MITIGATION_CVE_2020_0551").unwrap_or_default();
    match mitigation.as_ref() {
        "LOAD" => {
            build
                .flag(mitigation_cflags1)
                .flag(mitigation_cflags2)
                .flag(mitigation_asflags)
                .flag(mitigation_loadflags1)
                .flag(mitigation_loadflags2);
        }
        "CF" => {
            build
                .flag(mitigation_cflags1)
                .flag(mitigation_cflags2)
                .flag(mitigation_asflags)
                .flag(mitigation_cfflags1)
                .flag(mitigation_cfflags2);
        }
        _ => {}
    };
    build.compile("enclave_t");
    Ok(())
}

fn build_rust_enclave(native: &NativeTest, cmd: &TestOpt) -> Result<()> {
    let mut cargo = Command::new("cargo");
    cargo.arg("build");
    if !cmd.debug {
        cargo.arg("--release");
    }
    if cmd.backtrace {
        cargo.arg("--features");
        cargo.arg("backtrace");
    }
    cargo.arg("--manifest-path").arg("Cargo.toml");

    let src_dir = if cmd.debug {
        Path::new("./target/debug")
    } else {
        Path::new("./target/release")
    };

    let ret = run(&mut cargo);
    if ret {
        let mut out_name = OsString::from("lib");
        out_name.push("run_tests_enclave.a");
        let src_name = src_dir.join(&out_name);
        let timestamp = native.test_dir.join("build.timestamp");

        if !up_to_date(&src_name, &timestamp) {
            fs::copy(&src_name, &native.test_out_dir.join("libenclave.a"))
                .with_context(|| format!("Failed to copy file {}.", src_name.display()))?;
        }
        Ok(())
    } else {
        Err(anyhow!("Failed to compile rust encalve."))
    }
}

fn link_enclave(native: &NativeTest) -> Result<()> {
    let mut sdk_lib_dir = String::from("-L");
    sdk_lib_dir.push_str(native.sdk_dir.to_str().unwrap());
    sdk_lib_dir.push_str("/lib64");

    let edl_name = PathBuf::from("enclave.edl");
    let edl_name = edl_name.file_stem().context("EDL file name is invalid.")?;
    let mut object_name = edl_name.to_os_string();
    object_name.push("_t.o");
    let object = native.test_out_dir.join(&object_name);

    let ret = run(Command::new("gcc")
        .arg(&object)
        .arg("-o")
        .arg(&native.test_out_dir.join("enclave.so"))
        .arg("-Wl,--no-undefined")
        .arg("-nostdlib")
        .arg("-nodefaultlibs")
        .arg("-nostartfiles")
        .arg(&sdk_lib_dir)
        .arg("-Wl,--whole-archive")
        .arg("-lsgx_trts")
        .arg("-Wl,--no-whole-archive")
        .arg("-Wl,--start-group")
        .arg("-lsgx_tstdc")
        .arg("-lsgx_tcxx")
        .arg("-lsgx_tservice")
        .arg("-lsgx_tcrypto")
        .arg("-lsgx_tprotected_fs")
        //.arg("-lsgx_tkey_exchange")
        .arg("-L./out")
        .arg("-Wl,--whole-archive")
        .arg("-lenclave")
        .arg("-Wl,--no-whole-archive")
        .arg("-Wl,--end-group")
        .arg("-Wl,--version-script=enclave.lds")
        .arg("-Wl,-z,relro,-z,now,-z,noexecstack")
        .arg("-Wl,-Bstatic")
        .arg("-Wl,-Bsymbolic")
        .arg("-Wl,--no-undefined")
        .arg("-Wl,-pie,-eenclave_entry")
        .arg("-Wl,--export-dynamic")
        .arg("-Wl,--gc-sections")
        .arg("-Wl,--defsym,__ImageBase=0"));
    if ret {
        println!("LINK  => enclave.so");
        Ok(())
    } else {
        Err(anyhow!("Failed to link rust encalve."))
    }
}

fn sign_enclave(native: &NativeTest) -> Result<()> {
    let sign = native.sdk_dir.join("bin/x64/sgx_sign");
    let ret = run(Command::new(&sign)
        .arg("sign")
        .arg("-key")
        .arg(&native.test_dir.join("enclave.private.pem"))
        .arg("-enclave")
        .arg(&native.test_out_dir.join("enclave.so"))
        .arg("-out")
        .arg(&native.test_out_dir.join("enclave.signed.so"))
        .arg("-config")
        .arg(&native.test_dir.join("enclave.config.xml")));
    if ret {
        println!("SIGN  => enclave.signed.so");
        Ok(())
    } else {
        Err(anyhow!("Failed to sign encalve."))
    }
}

fn write_enclave_source(
    native: &NativeTest,
    cmd: &TestOpt,
    package_name: &str,
    _crate_name: &str,
) -> Result<()> {
    fs::create_dir_all(&native.test_src_dir).context("Failed to create test src dir.")?;

    let lib_name = native.test_src_dir.join("lib.rs");
    let toml = native.test_dir.join("Cargo.toml");
    let lds = native.test_dir.join("enclave.lds");
    let edl = native.test_dir.join("enclave.edl");
    let key = native.test_dir.join("enclave.private.pem");
    let config = native.test_dir.join("enclave.config.xml");

    let manifest_context = TEST_ENCLAVE_MANIFEST.replace("test_package_name", package_name);
    let config_context = format!(
        include_str!("../enclave.config.xml"),
        stack_size = cmd.stack_size,
        heap_size = cmd.heap_size,
        tcs_num = cmd.tcs_num
    );

    fs::write(&lib_name, TEST_ENCLAVE_LIB).context("Failed to write unittest enclave source")?;
    fs::write(&toml, &manifest_context).context("Failed to write unittest enclave manifest")?;
    fs::write(&lds, ENCLAVE_LDS).context("Failed to write unittest enclave lds")?;
    fs::write(&edl, ENCLAVE_EDL).context("Failed to write unittest enclave edl")?;
    fs::write(&key, ENCLAVE_KEY).context("Failed to write unittest enclave key")?;
    fs::write(&config, config_context).context("Failed to write unittest enclave config")?;

    Ok(())
}

fn run_vendor(native: &NativeTest) -> Result<()> {
    fs::create_dir_all(&native.test_vendor_dir).context("Failed to create test vendor dir.")?;

    let toml = native.test_dir.join("Cargo.toml");
    let ret = run(Command::new("cargo")
        .arg("vendor")
        .arg("--manifest-path")
        .arg(&toml)
        .arg(&native.test_vendor_dir)
        .stdout(Stdio::null()));
    //.stderr(Stdio::null()));
    if !ret {
        Err(anyhow!("Failed to run cargo vendor"))
    } else {
        let test_cargo_dir = native.test_dir.join(".cargo");
        let test_cargo_config = test_cargo_dir.join("config");
        if fs::create_dir_all(&test_cargo_dir).is_ok() {
            let _ = fs::write(&test_cargo_config, VENDOR_CONFIG);
        }
        Ok(())
    }
}

fn get_rust_metadata() -> Option<(String, String)> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path("../Cargo.toml")
        .exec()
        .ok()?;
    let root = metadata.resolve?.root?;

    let packages = &metadata.packages;
    let package = packages.into_iter().find(|&package| package.id == root)?;

    let package_name = package.name.clone();
    let targets = &package.targets;
    let target_name = targets
        .into_iter()
        .find(|&target| {
            let kinds = &target.kind;
            kinds
                .into_iter()
                .find(|&kind| kind == "rlib" || kind == "lib")
                .is_some()
        })
        .map(|t| t.name.clone())?;

    let crate_name = target_name.replace("-", "_");
    Some((package_name, crate_name))
}

