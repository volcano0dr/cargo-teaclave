use anyhow::{bail, Context};
use std::env;
use std::fs;
use std::fs::File;
use std::num::ParseIntError;
use std::path::PathBuf;
use structopt::StructOpt;

static TEST_DIR: &str = "teaclave-unittest";
static BUILD_DIR: &str = "teaclave-build";


#[derive(Debug, StructOpt)]
#[structopt(name = "cargo-teaclave", about = "Teaclave SGX unittest tool.")]
struct Opt {
    teaclave: Option<String>,
    #[structopt(subcommand)]
    command: TestCommand,
}

fn parse_hex(src: &str) -> Result<u64, ParseIntError> {
    u64::from_str_radix(src, 16)
}

#[derive(Debug, StructOpt)]
struct BuildOpt {
    #[structopt(long = "manifest-path", default_value = "./")]
    manifest_path: String,

    #[structopt(long, short, help = "debug build")]
    debug: bool,

    #[structopt(
        long = "edl",
        default_value = "Enclave.edl",
        help = "enclave edl file",
    )]
    edl: String,

    #[structopt(
        long = "config",
        default_value = "Enclave.config.xml",
        help = "enclave config file",
    )]
    config: String,

    #[structopt(
        long = "key",
        default_value = "Enclave_private.pem",
        help = "sign key file",
    )]
    key: String,

    #[structopt(
        long = "search-path",
        short = "S",
        help = "search edl path",
    )]
    search_path: Option<Vec<String>>,

    #[structopt(
        long = "include-path",
        short = "I",
        help = "include dir",
    )]
    include_path: Option<Vec<String>>,

    #[structopt(
        long = "link",
        short = "l",
        help = "link trusted staticlib",
    )]
    link_lib: Option<Vec<String>>,

    #[structopt(
        long = "link-path",
        short = "L",
        help = "search trusted staticlib path",
    )]
    link_path: Option<Vec<String>>,
}

#[derive(Debug, StructOpt)]
pub(crate) struct TestOpt {
    #[structopt(
        long = "manifest-path",
        default_value = "./",
        help = "Build and run unit test cases."
    )]
    manifest_path: String,

    #[structopt(long = "tcs_num", default_value = "3", help = "TCS number.")]
    pub tcs_num: u64,

    #[structopt(
        long = "stack-size",
        default_value = "400000",
        parse(try_from_str = parse_hex),
        help = "Stack max size.",
    )]
    pub stack_size: u64,

    #[structopt(
        long = "heap-size",
        default_value = "1000000",
        parse(try_from_str = parse_hex),
        help = "Heap max size.",
    )]
    pub heap_size: u64,

    #[structopt(long, short, help = "enable backtrace")]
    backtrace: bool,

    #[structopt(long, short, help = "debug build")]
    debug: bool,
}

#[derive(Debug, StructOpt)]
struct CleanOpt {
    #[structopt(
        long = "manifest-path",
        default_value = "./",
        help = "Remove the target directory, and Remove the unittest out directory."
    )]
    manifest_path: String,
}

#[derive(Debug, StructOpt)]
enum TestCommand {
    #[structopt(name = "build")]
    Build(BuildOpt),
    #[structopt(name = "test")]
    Test(TestOpt),
    #[structopt(name = "clean")]
    Clean(CleanOpt),
}

fn main() -> anyhow::Result<()> {
    let args = Opt::from_args();
    match args.command {
        TestCommand::Build(cmd) => build(&cmd)?,
        TestCommand::Test(cmd) => test(&cmd)?,
        TestCommand::Clean(cmd) => clean(&cmd)?,
    };
    Ok(())
}

fn build(cmd: &BuildOpt) -> anyhow::Result<()> {
    println!("build args: {:x?} \n\r", cmd);

    let native = NativeBuild::new(&cmd.manifest_path);
    if !native.src_dir.join("Cargo.toml").exists() {
        bail!(
            "Could not find `Cargo.toml` in {}.",
            &native.src_dir.display()
        );
    }
    env::set_current_dir(&native.src_dir).context("Failed to set working directory.")?;

    build::build_enclave(&native, &cmd)?;
    Ok(())
}

fn test(cmd: &TestOpt) -> anyhow::Result<()> {
    println!("test args: {:x?} \n\r", cmd);

    let native = NativeTest::new(&cmd.manifest_path);
    if !native.src_dir.join("Cargo.toml").exists() {
        bail!(
            "Could not find `Cargo.toml` in {}.",
            &native.src_dir.display()
        );
    }
    env::set_current_dir(&native.test_dir).context("Failed to set working directory.")?;

    test::build_test(&native, cmd)?;
    println!("\n");
    test::run_test(&native, cmd)?;

    Ok(())
}

fn clean(cmd: &CleanOpt) -> anyhow::Result<()> {
    let path = fs::canonicalize(&cmd.manifest_path).expect("The source directory is invalid.");
    if !path.join("Cargo.toml").exists() {
        bail!(
            "Could not find `Cargo.toml` in {}.",
            &path.display()
        );
    }
    env::set_current_dir(&path).context("Failed to set working directory.")?;
    clean::clean(&path)?;

    Ok(())
}

macro_rules! t {
    ($e:expr) => {
        match $e {
            Ok(e) => e,
            Err(e) => panic!("{} failed with {}", stringify!($e), e),
        }
    };
    ($e:expr, $extra:expr) => {
        match $e {
            Ok(e) => e,
            Err(e) => panic!("{} failed with {} ({:?})", stringify!($e), e, $extra),
        }
    };
}

pub(crate) struct NativeTest {
    pub(crate) sdk_dir: PathBuf,
    pub(crate) src_dir: PathBuf,
    pub(crate) test_dir: PathBuf,
    pub(crate) test_vendor_dir: PathBuf,
    pub(crate) test_src_dir: PathBuf,
    pub(crate) test_out_dir: PathBuf,
}

impl Drop for NativeTest {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            t!(File::create(self.test_dir.join("build.timestamp")));
        }
    }
}

impl NativeTest {
    pub fn new(src_dir: &str) -> NativeTest {
        let src_dir = fs::canonicalize(src_dir).expect("The source directory is invalid.");
        let sdk_dir =
            PathBuf::from(env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string()));

        let test_dir = src_dir.join(TEST_DIR);
        let test_vendor_dir = test_dir.join("vendor");
        let test_out_dir = test_dir.join("out");
        let test_src_dir = test_dir.join("src");

        fs::create_dir_all(&test_dir).expect("Failed to create test out dir.");

        NativeTest {
            sdk_dir,
            src_dir,
            test_dir,
            test_vendor_dir,
            test_src_dir,
            test_out_dir,
        }
    }
}

pub(crate) struct NativeBuild {
    pub(crate) sdk_dir: PathBuf,
    pub(crate) src_dir: PathBuf,
    pub(crate) build_dir: PathBuf,
    pub(crate) build_vendor_dir: PathBuf,
    pub(crate) build_src_dir: PathBuf,
    pub(crate) build_out_dir: PathBuf,
}

impl Drop for NativeBuild {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            t!(File::create(self.build_dir.join("build.timestamp")));
        }
    }
}

impl NativeBuild {
    pub fn new(src_dir: &str) -> NativeBuild {
        let src_dir = fs::canonicalize(src_dir).expect("The build src directory is invalid.");
        let sdk_dir =
            PathBuf::from(env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string()));

        let build_dir = src_dir.join(BUILD_DIR);
        let build_vendor_dir = build_dir.join("vendor");
        let build_out_dir = build_dir.join("out");
        let build_src_dir = build_dir.join("src");

        fs::create_dir_all(&build_dir).expect("Failed to create build dir.");

        NativeBuild {
            sdk_dir,
            src_dir,
            build_dir,
            build_vendor_dir,
            build_src_dir,
            build_out_dir,
        }
    }
}

mod test;
mod clean;
mod utils;
mod build;