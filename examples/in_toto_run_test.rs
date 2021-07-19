use in_toto::crypto::PrivateKey;
use in_toto::runlib::in_toto_run;

const ED25519_1_PRIVATE_KEY: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1");

fn main() {
    let key = PrivateKey::from_ed25519(ED25519_1_PRIVATE_KEY).unwrap();

    let link = in_toto_run(
        "example",
        Some("tests"),
        &["tests/test_runlib"],
        &["tests/test_runlib"],
        &["sh", "-c", "echo 'in_toto says hi' >> hello_intoto"],
        Some(&key),
        Some(&["sha512", "sha256"]),
    )
    .unwrap();
    let json = serde_json::to_value(&link).unwrap();

    println!("Generated link: {}", json)

}
