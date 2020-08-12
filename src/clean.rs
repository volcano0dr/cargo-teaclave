use crate::{BUILD_DIR, TEST_DIR};
use crate::utils::run;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use anyhow::Result;

pub(crate) fn clean(path: &PathBuf) -> Result<()> {
    let test_dir = path.join(TEST_DIR);
    let build_dir = path.join(BUILD_DIR);

    let _ = run(Command::new("cargo").arg("clean"));
    let _ = fs::remove_dir_all(&build_dir);
    let _ = fs::remove_dir_all(&test_dir);
    Ok(())
}
