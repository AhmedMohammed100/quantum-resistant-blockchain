use std::env;
use std::path::PathBuf;

fn main() {
    if env::var_os("CARGO_FEATURE_LIBOQS").is_none() {
        return;
    }

    let liboqs_dir = env::var_os("LIBOQS_DIR")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join("_oqs")))
        .unwrap_or_else(|| PathBuf::from("C:/Users/Ahmed/_oqs"));

    println!("cargo:rerun-if-env-changed=LIBOQS_DIR");
    println!("cargo:rustc-link-search=native={}", liboqs_dir.join("lib").display());
    println!("cargo:rustc-link-lib=oqs");
}
