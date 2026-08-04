//! Generate realistic synthetic datasets for exercising deident at scale.
//!
//! ```text
//! cargo run -p deident-core --example gen_dataset -- examples/data 1000
//! ```
//!
//! Produces three referentially consistent tables plus a deliberately messy
//! variant:
//!
//! | File | Purpose |
//! |---|---|
//! | `clinic-patients.csv` | direct identifiers, quasi-identifiers, free-text notes |
//! | `clinic-visits.csv`   | foreign key into patients — for chained runs |
//! | `clinic-labs.csv`     | a third table, JSONL-friendly, numeric payloads |
//! | `clinic-messy.csv`    | the same shape with real-world damage (see below) |
//!
//! Two properties make this useful rather than merely large:
//!
//! 1. **The quasi-identifier distribution is engineered.** Ages, ZIPs and dates
//!    are drawn so that most rows fall into large equivalence classes while a
//!    deliberate minority are unique. A uniformly random dataset makes every row
//!    unique, which makes the risk report look alarming and teaches nothing.
//! 2. **Free text carries every entity type the detectors know about**, at
//!    varying density, so `preset: all` has something to find.
//!
//! `clinic-messy.csv` adds what real exports actually contain: a UTF-8 BOM,
//! mixed-case headers, empty cells, unparsable dates, numbers that *look* like
//! payment cards but fail Luhn, zero-padded identifiers that a naive type
//! inference would corrupt, and non-ASCII names.
//!
//! Output is deterministic: a fixed seed and a small counter-based PRNG, so
//! regenerating gives byte-identical files and tests stay reproducible.

use std::fmt::Write as _;
use std::path::Path;

/// Counter-based PRNG over BLAKE3. Deterministic, no dependency on `rand`, and
/// good enough for shaping test data.
struct Rng {
    seed: [u8; 32],
    counter: u64,
}

impl Rng {
    fn new(seed: &str) -> Self {
        Self {
            seed: blake3::hash(seed.as_bytes()).into(),
            counter: 0,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut hasher = blake3::Hasher::new_keyed(&self.seed);
        hasher.update(&self.counter.to_le_bytes());
        self.counter += 1;
        u64::from_le_bytes(hasher.finalize().as_bytes()[..8].try_into().expect("8 bytes"))
    }

    /// Uniform in `0..n`.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    fn pick<'a, T>(&mut self, options: &'a [T]) -> &'a T {
        &options[self.below(options.len() as u64) as usize]
    }

    /// True with probability `percent`/100.
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

const GIVEN: &[&str] = &[
    "Alice", "Bruno", "Carla", "Deniz", "Erik", "Fatma", "Georg", "Hana", "Igor", "Julia",
    "Karim", "Lena", "Mehmet", "Nadia", "Olaf", "Petra", "Quentin", "Rosa", "Stefan", "Tanja",
    "Umut", "Vera", "Wolfgang", "Xenia", "Yusuf", "Zora", "Émile", "Søren", "Ingrid", "Müller",
];
const FAMILY: &[&str] = &[
    "Muster", "Beispiel", "Demo", "Test", "Probe", "Schmidt", "Weber", "Fischer", "Koch",
    "Bauer", "Wagner", "Becker", "Hoffmann", "Schäfer", "Krüger", "Yilmaz", "Nowak", "Rossi",
];
const WARDS: &[&str] = &[
    "cardiology", "pulmonology", "endocrinology", "orthopedics", "neurology", "general",
    "oncology", "nephrology",
];
const DIAGNOSES: &[&str] = &[
    "I10", "E11.9", "J45.909", "M54.5", "K21.0", "F32.1", "E78.5", "I25.10", "J06.9", "N18.3",
];

/// Free-text note templates, each seeded with entities the detectors should
/// find. `{}` placeholders are filled per row.
const NOTE_TEMPLATES: &[&str] = &[
    "follow-up in 6 weeks",
    "refund to DE89 3704 0044 0532 0130 00 approved",
    "contact patient at {email}",
    "callback +49 89 {digits4}{digits3}",
    "referred by Dr. {given} {family}",
    "treated at Apollo Hospital, transferred from HDFC Bank clinic",
    "history of diabetes and hypertension",
    "lives at {house} MG Road, Pune 411001",
    "portal access via https://internal.clinic.example/records/{id}",
    "insurance card 4111 1111 1111 1111 on file",
    "order ref 1234567890123 pending",
    "ssn 123-45-6789 verified",
    "passport J{digits7} checked",
    "vehicle MH 12 AB {digits4} in lot",
    "dob confirmed 15/03/1990",
    "vpn from 192.168.1.{octet} and 2001:db8::{octet}",
    "api token sk-live_{token} rotated",
    "ifsc HDFC0001234 000123456789 on record",
    "",
    "",
];

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().unwrap_or_else(|| "examples/data".to_string());
    let rows: usize = args
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(1000)
        .max(1);
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).expect("cannot create output directory");

    let mut rng = Rng::new("deident-synthetic-v1");
    let patients = build_patients(&mut rng, rows);
    let visits = build_visits(&mut rng, &patients);
    let labs = build_labs(&mut rng, &patients);
    let messy = build_messy(&mut rng, &patients);

    write(dir.join("clinic-patients.csv"), &patients.csv);
    write(dir.join("clinic-visits.csv"), &visits);
    write(dir.join("clinic-labs.jsonl"), &labs);
    write(dir.join("clinic-messy.csv"), &messy);

    println!(
        "Wrote {} patients, {} visits and {} lab rows to {}",
        patients.ids.len(),
        visits.lines().count().saturating_sub(1),
        labs.lines().count(),
        dir.display()
    );
    println!(
        "These are SYNTHETIC records containing deliberately planted identifiers. \
         Do not mix them with real data."
    );
}

struct Patients {
    csv: String,
    ids: Vec<String>,
}

fn build_patients(rng: &mut Rng, rows: usize) -> Patients {
    let mut csv = String::from(
        "patient_id,full_name,email,phone,age,zip,admission_date,diagnosis,notes\n",
    );
    let mut ids = Vec::with_capacity(rows);

    // A small pool of quasi-identifier combinations that most rows share, so
    // equivalence classes are large; a minority of rows get rare values and end
    // up unique. This is what makes the risk report instructive.
    let common_zips = ["81549", "81541", "80331", "80333", "85354"];
    let rare_zips = ["01067", "99998", "20095", "04103"];

    for i in 0..rows {
        let id = format!("P{:06}", i + 1);
        let given = rng.pick(GIVEN);
        let family = rng.pick(FAMILY);
        let common = rng.chance(85);
        let zip = if common {
            *rng.pick(&common_zips)
        } else {
            *rng.pick(&rare_zips)
        };
        // Ages cluster in decades for common rows, spread widely for rare ones.
        let age = if common {
            30 + rng.below(4) * 10 + rng.below(10)
        } else {
            18 + rng.below(75)
        };
        let month = 1 + rng.below(12);
        let day = 1 + rng.below(28);
        let year = if common { 2024 } else { 2019 + rng.below(6) };
        let email = format!(
            "{}.{}@example.{}",
            given.to_lowercase(),
            family.to_lowercase(),
            rng.pick(&["com", "org", "net"])
        );
        let note = render_note(rng, &id, given, family);

        let _ = writeln!(
            csv,
            "{id},{family}^{given},{email},+49 89 {:07},{age},{zip},{year}-{month:02}-{day:02},{},{}",
            rng.below(10_000_000),
            rng.pick(DIAGNOSES),
            quote(&note)
        );
        ids.push(id);
    }
    Patients { csv, ids }
}

fn render_note(rng: &mut Rng, id: &str, given: &str, family: &str) -> String {
    let template = *rng.pick(NOTE_TEMPLATES);
    template
        .replace("{email}", &format!("{}@example.com", given.to_lowercase()))
        .replace("{given}", given)
        .replace("{family}", family)
        .replace("{id}", id)
        .replace("{house}", &(1 + rng.below(400)).to_string())
        .replace("{octet}", &rng.below(255).to_string())
        .replace("{digits3}", &format!("{:03}", rng.below(1000)))
        .replace("{digits4}", &format!("{:04}", rng.below(10_000)))
        .replace("{digits7}", &format!("{:07}", rng.below(10_000_000)))
        .replace("{token}", &format!("{:016x}", rng.next_u64()))
}

/// Visits reference patients by a differently named column, so a chained run
/// needs `pseudonymize.domain` to keep the join working.
fn build_visits(rng: &mut Rng, patients: &Patients) -> String {
    let mut csv = String::from("visit_id,patient_ref,visit_date,ward,cost_eur\n");
    let mut visit = 0u64;
    for id in &patients.ids {
        // Most patients have 1–3 visits; some have none.
        let count = match rng.below(10) {
            0 => 0,
            1..=5 => 1,
            6..=8 => 2,
            _ => 3,
        };
        for _ in 0..count {
            visit += 1;
            let _ = writeln!(
                csv,
                "V{visit:07},{id},2024-{:02}-{:02},{},{}.{:02}",
                1 + rng.below(12),
                1 + rng.below(28),
                rng.pick(WARDS),
                20 + rng.below(500),
                rng.below(100)
            );
        }
    }
    csv
}

/// A JSONL table, so the JSONL reader gets exercised by the examples too.
/// Includes a zero-padded string field and a genuine float, which is where
/// naive type re-inference goes wrong.
fn build_labs(rng: &mut Rng, patients: &Patients) -> String {
    let mut out = String::new();
    for (i, id) in patients.ids.iter().enumerate() {
        if !rng.chance(70) {
            continue;
        }
        let _ = writeln!(
            out,
            r#"{{"lab_id":"L{:07}","patient_ref":"{id}","sample_code":"{:05}","hba1c":{}.{},"flagged":{},"comment":"{}"}}"#,
            i + 1,
            rng.below(100_000),
            4 + rng.below(9),
            rng.below(10),
            rng.chance(20),
            if rng.chance(15) {
                "recheck, contact lab@example.org"
            } else {
                "within range"
            }
        );
    }
    out
}

/// The same patient shape, damaged the way real exports are.
fn build_messy(rng: &mut Rng, patients: &Patients) -> String {
    // Leading BOM and inconsistent header casing: both make an exact-match
    // policy field silently inert.
    let mut csv = String::from("\u{feff}Patient_ID,full_name,EMail,age,zip,admission_date,notes\n");
    for (i, id) in patients.ids.iter().take(patients.ids.len().min(200)).enumerate() {
        let broken_date = match i % 5 {
            0 => "unknown".to_string(),
            1 => "14.03.2024".to_string(),      // German order, unparsable as ISO
            2 => String::new(),                  // missing
            _ => format!("2024-{:02}-{:02}", 1 + rng.below(12), 1 + rng.below(28)),
        };
        let age = if i % 7 == 0 { String::new() } else { (20 + rng.below(60)).to_string() };
        let note = match i % 6 {
            0 => "order 4532123456789012 shipped".to_string(), // card-shaped, fails Luhn
            1 => "ref 0001234 zero-padded".to_string(),        // corrupted by re-typing
            2 => "Müller, Sören — umlauts".to_string(),
            3 => "meeting at 12:30 only".to_string(),          // not an IP
            4 => "version 1.2.3.4 of the app".to_string(),     // looks like IPv4
            _ => String::new(),
        };
        let _ = writeln!(
            csv,
            "{id},{},{},{age},{},{broken_date},{}",
            quote(&format!("{}^{}", rng.pick(FAMILY), rng.pick(GIVEN))),
            if i % 4 == 0 { String::new() } else { format!("user{i}@example.com") },
            if i % 9 == 0 { "0".repeat(5) } else { format!("{:05}", 80000 + rng.below(9999)) },
            quote(&note)
        );
    }
    csv
}

/// Minimal CSV quoting: only when the value needs it.
fn quote(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn write(path: std::path::PathBuf, contents: &str) {
    std::fs::write(&path, contents)
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}
