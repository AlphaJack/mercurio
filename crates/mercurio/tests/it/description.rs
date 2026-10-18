//! The README and the AUR package can not read `Cargo.toml`, so their copy of the description is checked against it.

const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

fn workspace_file(path: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(path)).unwrap()
}

#[test]
fn readme_and_pkgbuild_carry_the_cargo_description() {
    assert!(workspace_file("README.md").contains(DESCRIPTION), "README.md must contain the Cargo.toml description");
    assert!(
        workspace_file("packaging/aur/PKGBUILD").contains(&format!("pkgdesc=\"{DESCRIPTION}\"")),
        "PKGBUILD pkgdesc must be the Cargo.toml description"
    );
}
