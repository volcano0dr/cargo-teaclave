use crate::BuildOpt;
use crate::NativeBuild;
use crate::utils::{run, up_to_date};
use crate::utils::ENCLAVE_LDS;
use anyhow::{anyhow, bail, Context, Result};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

static VENDOR_LIB: &str = include_str!("../teaclave-build.rs");
static VENDOR_MANIFEST: &str = include_str!("../teaclave-build.toml");

pub(crate) fn build_enclave(native: &NativeBuild, cmd: &BuildOpt) -> Result<()> {
    fs::create_dir_all(&native.build_out_dir).context("Failed to create build out dir.")?;
    fs::create_dir_all(&native.build_src_dir).expect("Failed to create build src dir.");

    let edl_dir = native.build_vendor_dir.join("sgx_edl/edl");
    let common_dir = native.build_vendor_dir.join("sgx_edl/common");
    if !edl_dir.exists() || !common_dir.exists() {
        run_vendor(&native)?;
    }

    let timestamp = native.build_dir.join("build.timestamp");
    if !native.build_out_dir.join("libenclave_t.a").exists()
        || !up_to_date(Path::new(&cmd.edl), &timestamp)
    {
        build_edl(&native, &cmd)?;
    }

    let mut target_name = build_rust_enclave(&native, cmd.debug)?;

    if !native.build_out_dir.join("enclave.so").exists()
        || !up_to_date(&native.build_out_dir.join("libenclave.a"), &timestamp)
        || !up_to_date(&native.build_out_dir.join("libenclave_t.a"), &timestamp)
    {
        link_enclave(&native, &cmd)?;
    }

    target_name.push(".signed.so");
    if !native.build_out_dir.join(&target_name).exists()
        || !up_to_date(&native.build_out_dir.join("enclave.so"), &timestamp)
        || !up_to_date(Path::new(&cmd.config), &timestamp)
        || !up_to_date(Path::new(&cmd.key), &timestamp)
    {
        let sign = native.sdk_dir.join("bin/x64/sgx_sign");
        let ret = run(Command::new(&sign)
            .arg("sign")
            .arg("-key")
            .arg(&cmd.key)
            .arg("-enclave")
            .arg(&native.build_out_dir.join("enclave.so"))
            .arg("-out")
            .arg(&native.build_out_dir.join(&target_name))
            .arg("-config")
            .arg(&cmd.config));
        if ret {
            println!("SIGN  => {}", target_name.to_str().unwrap());
        } else {
            bail!("Failed to sign enclave.");
        }
    }

    println!("\n\rBuild SGX enclave success!");
    Ok(())
}

fn run_vendor(native: &NativeBuild) -> Result<()> {
    fs::create_dir_all(&native.build_vendor_dir).context("Failed to create build vendor dir.")?;

    let lib_name = native.build_src_dir.join("lib.rs");
    let toml = native.build_dir.join("Cargo.toml");
    fs::write(&lib_name, VENDOR_LIB).context("Failed to write vendor info")?;
    fs::write(&toml, VENDOR_MANIFEST).context("Failed to write vendor info")?;

    let ret = run(Command::new("cargo")
        .arg("vendor")
        .arg("--manifest-path")
        .arg(&toml)
        .arg(&native.build_vendor_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null()));
    if !ret {
        Err(anyhow!("Failed to run cargo vendor"))
    } else {
        Ok(())
    }
}

fn build_edl(native: &NativeBuild, cmd: &BuildOpt) -> Result<()> {
    let edger8r = native.sdk_dir.join("bin/x64/sgx_edger8r");
    let ret = run(Command::new(&edger8r)
        .arg("--trusted")
        .arg(&cmd.edl)
        .arg("--search-path")
        .arg(&native.build_vendor_dir.join("sgx_edl/edl"))
        .arg("--search-path")
        .arg(&native.build_vendor_dir.join("sgx_edl/edl/intel"))
        .arg("--trusted-dir")
        .arg(&native.build_out_dir));
    if !ret {
        bail!("Failed to run sgx_edger8r.");
    }

    let edl_name = PathBuf::from(&cmd.edl);
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
        .include(&native.build_vendor_dir.join("sgx_edl/edl"))
        .include(&native.build_vendor_dir.join("sgx_edl/common/inc"))
        .include(&native.sdk_dir.join("include"))
        .include(&native.sdk_dir.join("include/tlibc"))
        .include(&native.sdk_dir.join("include/llibcxx"))
        .include(&native.sdk_dir.join("include/ipp"))
        .out_dir(&native.build_out_dir)
        .warnings(false)
        .file(&native.build_out_dir.join(&t_c))
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

fn build_rust_enclave(native: &NativeBuild, debug: bool) -> Result<OsString> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build");
    if !debug {
        cmd.arg("--release");
    }
    cmd.arg("--manifest-path").arg("Cargo.toml");

    let src_dir = if debug {
        Path::new("./target/debug")
    } else {
        Path::new("./target/release")
    };

    let ret = run(&mut cmd);
    if ret {
        let name = get_rust_target_name().context("Failed to get target name.")?;
        let mut out_name = OsString::from("lib");
        out_name.push(&name);
        out_name.push(".a");
        let src_name = src_dir.join(&out_name);
        let timestamp = native.build_dir.join("build.timestamp");

        if !up_to_date(&src_name, &timestamp) {
            fs::copy(&src_name, &native.build_out_dir.join("libenclave.a"))
                .with_context(|| format!("Failed to copy file {}.", src_name.display()))?;
        }
        Ok(name)
    } else {
        Err(anyhow!("Failed to compile rust encalve."))
    }
}

fn link_enclave(native: &NativeBuild, cmd: &BuildOpt) -> Result<()> {
    let mut sdk_lib_dir = String::from("-L");
    sdk_lib_dir.push_str(native.sdk_dir.to_str().unwrap());
    sdk_lib_dir.push_str("/lib64");

    let lds = native.build_out_dir.join("enclave.lds");
    fs::write(&lds, ENCLAVE_LDS).context("Failed to write enclave.lds file.")?;

    let edl_name = PathBuf::from(&cmd.edl);
    let edl_name = edl_name.file_stem().context("EDL file name is invalid.")?;
    let mut object_name = edl_name.to_os_string();
    object_name.push("_t.o");
    let object = native.build_out_dir.join(&object_name);

    let mut tcmalloc = false;
    let mut link_lib: Vec<String> = Vec::new();
    if let Some(libs) = cmd.link_lib.as_ref() {
        link_lib = libs
            .into_iter()
            .filter(|&lib| {
                if lib.as_str() == "sgx_tcmalloc" {
                    tcmalloc = true;
                    false
                } else {
                    true
                }
            })
            .map(|lib| {
                let mut arg = String::from("-l");
                arg.push_str(lib.as_str());
                arg
            })
            .collect();
    }

    let mut link_path: Vec<String> = Vec::new();
    if let Some(paths) = cmd.link_path.as_ref() {
        link_path = paths
            .into_iter()
            .map(|path| {
                let mut arg = String::from("-L");
                arg.push_str(path.as_str());
                arg
            })
            .collect();
    }

    let mut cc = Command::new("gcc");
    cc.arg(&object)
        .arg("-o")
        .arg(&native.build_out_dir.join("enclave.so"))
        .arg("-Wl,--no-undefined")
        .arg("-nostdlib")
        .arg("-nodefaultlibs")
        .arg("-nostartfiles")
        .arg(&sdk_lib_dir)
        .arg("-L./teaclave-build/out");

    for link_arg in &link_path {
        cc.arg(link_arg);
    }

    cc.arg("-Wl,--whole-archive");
    if tcmalloc {
        cc.arg("-lsgx_tcmalloc");
    }
    cc.arg("-lsgx_trts").arg("-Wl,--no-whole-archive");

    cc.arg("-Wl,--start-group")
        .arg("-lsgx_tstdc")
        .arg("-lsgx_tservice")
        .arg("-lsgx_tcrypto");
    for link_arg in &link_lib {
        cc.arg(link_arg);
    }
    cc.arg("-lenclave").arg("-Wl,--end-group");

    cc.arg("-Wl,--version-script=./teaclave-build/out/enclave.lds")
        .arg("-Wl,-z,relro,-z,now,-z,noexecstack")
        .arg("-Wl,-Bstatic")
        .arg("-Wl,-Bsymbolic")
        .arg("-Wl,--no-undefined")
        .arg("-Wl,-pie,-eenclave_entry")
        .arg("-Wl,--export-dynamic")
        .arg("-Wl,--gc-sections")
        .arg("-Wl,--defsym,__ImageBase=0");

    let ret = run(&mut cc);
    if ret {
        println!("LINK  => enclave.so");
        Ok(())
    } else {
        Err(anyhow!("Failed to link rust encalve."))
    }
}

fn get_rust_target_name() -> Option<OsString> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path("./Cargo.toml")
        .exec()
        .ok()?;
    let root = metadata.resolve?.root?;

    let packages = &metadata.packages;
    let package = packages.into_iter().find(|&package| package.id == root)?;

    let targets = &package.targets;
    targets
        .into_iter()
        .find(|&target| {
            let kinds = &target.kind;
            kinds
                .into_iter()
                .find(|&kind| kind == "staticlib")
                .is_some()
        })
        .map(|t| OsString::from(&t.name))
}
