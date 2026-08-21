//! Guards the README's detector table against drift.
//!
//! This project documents a lot of behaviour, and a docs table that quietly
//! disagrees with the code is worse than no table: someone decides whether a
//! match is trustworthy by reading it. So the table is asserted against the
//! catalog rather than maintained by hand.

use deident_core::detect::{ALL, Validator};

/// The README lives at the workspace root, two levels up from this crate.
fn readme() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Rows of the built-in detector table: `| \`name\` | example | class | validated |`.
fn table_rows(readme: &str) -> Vec<&str> {
    readme
        .lines()
        .filter(|line| line.starts_with("| `") && line.matches('|').count() >= 5)
        .collect()
}

#[test]
fn every_detector_appears_in_the_readme_table_with_the_right_class() {
    let readme = readme();
    let rows = table_rows(&readme);
    for builtin in ALL {
        let name = builtin.name();
        let row = rows
            .iter()
            .find(|line| line.starts_with(&format!("| `{name}` ")))
            .unwrap_or_else(|| panic!("detector '{name}' is missing from the README table"));
        assert!(
            row.contains(builtin.precision().label()),
            "detector '{name}': README row does not state its precision class \
             ({}): {row}",
            builtin.precision().label()
        );
    }
}

/// A ✅ in the table means "a validator runs for this detector". Claiming
/// verification the code does not perform would mislead someone into trusting a
/// match; omitting one that does run undersells the tool. Both are bugs.
#[test]
fn the_readme_marks_exactly_the_validated_detectors() {
    let readme = readme();
    let rows = table_rows(&readme);
    for builtin in ALL {
        let name = builtin.name();
        let row = rows
            .iter()
            .find(|line| line.starts_with(&format!("| `{name}` ")))
            .unwrap_or_else(|| panic!("detector '{name}' missing from the README table"));
        let documented = row.contains('✅');
        let actual = builtin.validator() != Validator::None;
        assert_eq!(
            documented, actual,
            "detector '{name}': README says validated={documented}, code says {actual}"
        );
    }
}

#[test]
fn the_readme_states_the_correct_validated_count() {
    let readme = readme();
    let validated = ALL
        .iter()
        .filter(|b| b.validator() != Validator::None)
        .count();
    assert_eq!(validated, 9, "if this changed, update the README prose too");
    assert_eq!(ALL.len(), 17, "if this changed, update the README prose too");
    for claim in [
        "**Nine of the seventeen are validated**",
        "17 built-in detectors",
    ] {
        assert!(
            readme.contains(claim),
            "the README should state {claim:?} — it is now out of date"
        );
    }
}
