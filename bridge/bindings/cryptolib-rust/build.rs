// Locate the bundled native library for the host target and wire up linker +
// rpath so the produced binary/test loads it without `DYLD_LIBRARY_PATH`.
use std::env;
use std::path::PathBuf;

fn main() {
    let os = match env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "macos"   => "darwin",
        "windows" => "win32",
        s         => s.to_string().leak() as &str,
    };
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64"  => "x86_64",
        "aarch64" => "arm64",
        s         => s.to_string().leak() as &str,
    };
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lib_dir = manifest_dir.join("native").join(format!("{os}-{arch}"));

    println!("cargo:rerun-if-changed={}", lib_dir.display());
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=cryptolib_c");

    // Bake the absolute path into the produced binary's rpath so it loads the
    // bundled dylib without DYLD_LIBRARY_PATH. Fine for local dev/tests; a
    // published crate would use @rpath + a real install layout.
    if os == "darwin" {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    } else if os == "linux" {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    }
}
